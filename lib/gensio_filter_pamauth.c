#include "gensio_filter_pamauth.h"

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>

#include <security/pam_appl.h>

#include <assert.h>
#include <string.h>

struct gensio_pamauth_filter_data {
    struct gensio_os_funcs *o;

    bool allow_authfail;
    bool use_child_auth;

    /*
     * The following is only used for testing. so pamauth can be run
     * over stdio for fuzz testing.  Do not document.
     */
    bool allow_unencrypted;
};

#define GENSIO_PAMAUTH_DATA_SIZE 2048

#define PAMAUTH_RESULT_SUCCESS	1
#define PAMAUTH_RESULT_FAILURE	2
#define PAMAUTH_RESULT_ERR	3

/*
 * Ambiguity in spec: is it an array of pointers or a pointer to an array?
 * Stolen from openssh.
 */
#ifdef PAM_SUN_CODEBASE
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#else
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
#endif

enum pamauth_state {
    PAMAUTH_AUTHENTICATE,
    PAMAUTH_REQUEST,
    PAMAUTH_RESPONSE,
    PAMAUTH_PASSTHROUGH,
    PAMAUTH_ERROR,
};

struct pamauth_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;


    enum pamauth_state state;
    bool allow_authfail;
    bool use_child_auth;

    pam_handle_t *pamh;
    struct pam_conv pam_conv;
    int pam_num_msg;
    int pam_msg_idx;

    struct pam_message *pam_msg;
    struct pam_response *pam_resp;

    char *response_buf;
    gensiods response_len;

    unsigned char *read_buf;
    gensiods read_buf_len;
    gensiods max_read_size;

    unsigned char *write_buf;
    gensiods write_buf_len;
    gensiods write_buf_pos;
    gensiods max_write_size;

    bool got_msg;

    /*
     * If we get an error while reading, hold it here until the try
     * connect is called.
     */
    int pending_err;
};

#define filter_to_pamauth(v) ((struct pamauth_filter *) \
			       gensio_filter_get_user_data(v))


void
gensio_pamauth_filter_config_free(struct gensio_pamauth_filter_data *data)
{
    struct gensio_os_funcs *o;

    if (!data)
	return;

    o = data->o;
    o->free(o, data);
}

int
gensio_pamauth_filter_config(struct gensio_os_funcs *o,
			     const char * const args[],
			     struct gensio_pamauth_filter_data **rdata)
{
    unsigned int i;
    struct gensio_pamauth_filter_data *data = o->zalloc(o, sizeof(*data));
    int rv = GE_NOMEM, ival;
    const char *str;
    char *fstr;

    if (!data)
	return GE_NOMEM;
    data->o = o;

    rv = gensio_get_default(o, "pamauth", "allow-authfail", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    data->allow_authfail = ival;

    rv = gensio_get_default(o, "pamauth", "use-child-auth", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    data->use_child_auth = ival;

    rv = GE_NOMEM;
    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keybool(args[i], "allow-authfail",
				 &data->allow_authfail) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "use-child-auth",
				 &data->use_child_auth) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "allow-unencrypted",
				 &data->allow_unencrypted) > 0)
	    continue;
	rv = GE_INVAL;
	goto out_err;
    }

    *rdata = data;

    return 0;
 out_err:
    gensio_pamauth_filter_config_free(data);
    return rv;
}

static void
sfilter_free(struct pamauth_filter *sfilter)
{
    if (sfilter->lock)
	sfilter->o->free_lock(sfilter->lock);
    if (sfilter->read_buf) {
	memset(sfilter->read_buf, 0, sfilter->max_read_size);
	sfilter->o->free(sfilter->o, sfilter->read_buf);
    }
    if (sfilter->write_buf)
	sfilter->o->free(sfilter->o, sfilter->write_buf);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    sfilter->o->free(sfilter->o, sfilter);
}

static void
pamauth_lock(struct pamauth_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
pamauth_unlock(struct pamauth_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
pamauth_set_callbacks(struct gensio_filter *filter,
		  gensio_filter_cb cb, void *cb_data)
{
    /* We don't currently use callbacks. */
}

static bool
pamauth_ul_read_pending(struct gensio_filter *filter)
{
    return false; /* We never have data pending to the upper layer. */
}

static bool
pamauth_ll_write_pending(struct gensio_filter *filter)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);

    return sfilter->write_buf_len > 0;
}

static bool
pamauth_ll_read_needed(struct gensio_filter *filter)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);

    /*
     * Turn off read when we have a message to process.
     */
    return !sfilter->got_msg;
}

static int
pamauth_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    /* TODO */
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);
    int rv = 0;

    pamauth_lock(sfilter);

    if (sfilter->state == PAMAUTH_PASSTHROUGH)
        gensio_set_is_authenticated(io, true);
    else
	rv = GE_AUTHREJECT;

    pamauth_unlock(sfilter);
    return rv;
}

static void
pamauth_write(struct pamauth_filter *sfilter, const void *data, unsigned int len)
{
    if (len + sfilter->write_buf_len > sfilter->max_write_size) {
	gensio_log(sfilter->o, GENSIO_LOG_ERR, "Unable to write data to network");
	sfilter->pending_err = GE_TOOBIG;
	return;
    }
    memcpy(sfilter->write_buf + sfilter->write_buf_len, data, len);
    sfilter->write_buf_len += len;
}

static void
pamauth_write_str(struct pamauth_filter *sfilter, const char *str)
{
    pamauth_write(sfilter, str, strlen(str));
}

static int
pamauth_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);
    struct gensio *io;
    gensiods len;
    bool password_requested = false;
    int err, pam_err, i;
    int rv;
    struct pam_message *msg;

    pamauth_lock(sfilter);

    if (sfilter->pending_err) {
	rv = sfilter->pending_err;
	goto exit;
    }
    if (!sfilter->got_msg) {
	rv = GE_INPROGRESS;
	goto exit;
    }

    if (sfilter->state == PAMAUTH_RESPONSE) {
	sfilter->pam_msg_idx++;

	if (sfilter->pam_msg_idx == sfilter->pam_num_msg) {
	    sfilter->state = PAMAUTH_AUTHENTICATE;
	} else {
	    sfilter->state = PAMAUTH_REQUEST;
	}
    }

    if (sfilter->state == PAMAUTH_AUTHENTICATE) {
	sfilter->write_buf_len = 0; /* TODO */
	sfilter->read_buf_len = 0;

	pam_err = pam_authenticate(sfilter->pamh, PAM_SILENT);
	if (pam_err == PAM_SUCCESS) {
	    /* TODO: Check more things? see gtlsshd */
	    sfilter->state = PAMAUTH_PASSTHROUGH;
	    rv = 0;
	} else if (pam_err == PAM_AUTHINFO_UNAVAIL && sfilter->pam_num_msg > 0) {
	    sfilter->state = PAMAUTH_REQUEST;
	    rv = GE_INPROGRESS;
	} else {
	    gensio_log(sfilter->o, GENSIO_LOG_ERR,
		"PAM authentication failed: %s (%d)",
		pam_strerror(sfilter->pamh, pam_err),
		pam_err
	    );
	    sfilter->state = PAMAUTH_ERROR;
	    rv = GE_AUTHREJECT;
	}
    }

    if (sfilter->state == PAMAUTH_REQUEST) {
	do {
	    msg = &sfilter->pam_msg[ sfilter->pam_msg_idx ];

	    pamauth_write_str(sfilter, msg->msg);

	    if (msg->msg_style == PAM_ERROR_MSG) {
		sfilter->state = PAMAUTH_ERROR;
		rv = GE_AUTHREJECT;
		break;
	    }
	    if (msg->msg_style == PAM_PROMPT_ECHO_ON
		|| msg->msg_style == PAM_PROMPT_ECHO_OFF
	    ) {
		/* TODO: Switch off echo on PAM_PROMPT_ECHO_OFF */
		sfilter->state = PAMAUTH_RESPONSE;
		sfilter->response_len = 0;
		sfilter->response_buf = sfilter->pam_resp[ sfilter->pam_msg_idx ].resp;
		rv = GE_INPROGRESS;
		break;
	    }

	    sfilter->pam_msg_idx++;
	} while(msg->msg_style == PAM_TEXT_INFO);
    }

    sfilter->got_msg = false;

exit:
    pamauth_unlock(sfilter);
    return rv;
}

static int
pamauth_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static int
pamauth_ul_write(struct gensio_filter *filter,
		  gensio_ul_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  const struct gensio_sg *sg, gensiods sglen,
		  const char *const *auxdata)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);
    int rv = 0;

    pamauth_lock(sfilter);
    if (sg) {
	if (sfilter->state != PAMAUTH_PASSTHROUGH || sfilter->pending_err)
	    rv = GE_NOTREADY;
	else
	    rv = handler(cb_data, rcount, sg, sglen, auxdata);
	if (rv)
	    goto out_unlock;
    }

    if (sfilter->write_buf_len) {
	gensiods count = 0;
	struct gensio_sg sg = { sfilter->write_buf + sfilter->write_buf_pos,
			      sfilter->write_buf_len - sfilter->write_buf_pos };

	rv = handler(cb_data, &count, &sg, 1, auxdata);
	if (rv)
	    goto out_unlock;
	if (count + sfilter->write_buf_pos >= sfilter->write_buf_len) {
	    sfilter->write_buf_len = 0;
	    sfilter->write_buf_pos = 0;
	} else {
	    sfilter->write_buf_pos += count;
	}
    }

 out_unlock:
    pamauth_unlock(sfilter);
    return rv;
}

static int
pamauth_ll_write(struct gensio_filter *filter,
		  gensio_ll_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  unsigned char *buf, gensiods buflen,
		  const char *const *auxdata)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);
    int err = 0, i;
    unsigned char *obuf = buf;
    unsigned char *nl;
    gensiods chunklen;

    if (buflen == 0)
	goto out;

    pamauth_lock(sfilter);
    if (sfilter->state == PAMAUTH_PASSTHROUGH) {
	pamauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter, GENSIO_EVENT_READ, 0,
				     buf, &buflen, auxdata);
	if (rcount)
	    *rcount = buflen;
	return err;
    }

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data. */
	if (rcount)
	    *rcount = buflen;
	goto out_unlock;
    }

    if (sfilter->pending_err) {
	if (rcount)
	    *rcount = buflen;
	goto out_unlock;
    }

    if (sfilter->state != PAMAUTH_RESPONSE) {
	/* Ignore data in that state */
	if (rcount)
	    *rcount = buflen;
	goto out_unlock;
    }

    nl = memchr(buf, '\n', buflen);
    if (!nl) {
	/* No newline found. Just copy into our receive buffer if it fits */

	if (sfilter->response_len + buflen > PAM_MAX_RESP_SIZE) {
	    sfilter->pending_err = GE_NOMEM;
	    goto out_unlock;
	}

	memcpy(sfilter->response_buf + sfilter->response_len, buf, buflen);
	sfilter->response_len += buflen;
	buf += buflen;

	goto out_unlock;
    }

    chunklen = nl - buf + 1;

    if (sfilter->response_len + chunklen > PAM_MAX_RESP_SIZE) {
	sfilter->pending_err = GE_NOMEM;
	goto out_unlock;
    }

    memcpy(sfilter->response_buf + sfilter->response_len, buf, chunklen);
    sfilter->response_len += chunklen;
    sfilter->response_buf[sfilter->response_len - 1] = '\0';
    buf += chunklen;

    sfilter->got_msg = true;

 out_unlock:
    err = sfilter->pending_err;
    pamauth_unlock(sfilter);
 out:
    if (rcount)
	*rcount = buf - obuf;

    return err;
}

static int
pamauth_setup(struct gensio_filter *filter)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);

    return 0;
}

static void
pamauth_cleanup(struct gensio_filter *filter)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);

    sfilter->pending_err = 0;
    sfilter->read_buf_len = 0;
    sfilter->write_buf_len = 0;
    sfilter->write_buf_pos = 0;
}

static void
pamauth_free(struct gensio_filter *filter)
{
    struct pamauth_filter *sfilter = filter_to_pamauth(filter);

    sfilter_free(sfilter);
}

static
int gensio_pamauth_filter_func(struct gensio_filter *filter, int op,
				void *func, void *data,
				gensiods *count,
				void *buf, const void *cbuf,
				gensiods buflen,
				const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	pamauth_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return pamauth_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return pamauth_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return pamauth_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return pamauth_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return pamauth_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return pamauth_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return pamauth_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return pamauth_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return pamauth_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	pamauth_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	pamauth_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
    case GENSIO_FILTER_FUNC_TIMEOUT:
    default:
	return GE_NOTSUP;
    }
}

static int
pam_conversation_cb(int num_msg, const struct pam_message **msg,
		    struct pam_response **resp, void *appdata_ptr)
{
    struct pamauth_filter *sfilter = appdata_ptr;
    struct gensio_os_funcs *o = sfilter->o;
    int i;

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
	return PAM_CONV_ERR;

    if (sfilter->pam_msg == NULL) {
	/* Copy messages */
	/* TODO free all the things! */
	sfilter->pam_msg_idx = 0;
	sfilter->pam_num_msg = num_msg;
	sfilter->pam_msg = o->zalloc(o, sizeof(struct pam_message) * num_msg);

	for (i = 0; i < num_msg; i++) {
	    gensio_log(sfilter->o,
		GENSIO_LOG_ERR,
		"PAM message: %s",
		PAM_MSG_MEMBER(msg, i, msg)
	    );
	    sfilter->pam_msg[i].msg_style = PAM_MSG_MEMBER(msg, i, msg_style);
	    sfilter->pam_msg[i].msg = gensio_strdup(o, PAM_MSG_MEMBER(msg, i, msg));
	}

	sfilter->pam_resp = o->zalloc(o, sizeof(struct pam_response) * num_msg);
	for (i = 0; i < num_msg; i++) {
	    sfilter->pam_resp[i].resp = o->zalloc(o, PAM_MAX_RESP_SIZE);
	}

	return PAM_CONV_AGAIN;
    } else {
	for (i = 0; i < sfilter->pam_num_msg; i++) {
	    o->free(o, (char *)sfilter->pam_msg[i].msg);
	}
	o->free(o, sfilter->pam_msg);
	sfilter->pam_msg = NULL;

	*resp = sfilter->pam_resp; /* This is free'd by the caller */
	sfilter->pam_resp = NULL;

	return PAM_SUCCESS;
    }
}

int
gensio_pamauth_filter_alloc(struct gensio_pamauth_filter_data *data,
			    struct gensio_filter **rfilter)
{
    struct gensio_os_funcs *o = data->o;
    struct gensio_filter *filter;
    struct pamauth_filter *sfilter;
    int rv, pam_err;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return GE_NOMEM;

    sfilter->o = o;
    sfilter->allow_authfail = data->allow_authfail;
    sfilter->use_child_auth = data->use_child_auth;

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    sfilter->state = PAMAUTH_AUTHENTICATE;
    sfilter->got_msg = true; /* Go ahead and run the state machine. */

    sfilter->read_buf = o->zalloc(o, GENSIO_PAMAUTH_DATA_SIZE);
    if (!sfilter->read_buf)
	goto out_nomem;
    sfilter->max_read_size = GENSIO_PAMAUTH_DATA_SIZE;

    sfilter->write_buf = o->zalloc(o, GENSIO_PAMAUTH_DATA_SIZE);
    if (!sfilter->write_buf)
	goto out_nomem;
    sfilter->max_write_size = GENSIO_PAMAUTH_DATA_SIZE;

    sfilter->filter = gensio_filter_alloc_data(o, gensio_pamauth_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    sfilter->pam_conv.conv = pam_conversation_cb;
    sfilter->pam_conv.appdata_ptr = sfilter;
    /* TODO pam_end() */
    pam_err = pam_start(
	"ser2net", /* TODO: Do not hard code */
	"bob",     /* TODO: Add an option to specify user and ask if not set */
	&sfilter->pam_conv,
	&sfilter->pamh
    );
    if (pam_err != PAM_SUCCESS) {
	gensio_log(sfilter->o,
	    GENSIO_LOG_ERR,
	    "Unable to start PAM transaction: %s",
	    pam_strerror(sfilter->pamh, pam_err)
	);
	goto out_err;
    }

    *rfilter = sfilter->filter;
    return 0;

 /* TODO: clean up properly */
 out_nomem:
    rv = GE_NOMEM;
 out_err:
    sfilter_free(sfilter);
    return rv;
}
