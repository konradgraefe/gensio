#include "gensio_filter_pamauth.h"

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>

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

enum pamauth_state {
    PAMAUTH_PROMPT,
    PAMAUTH_PASSWORD,
    PAMAUTH_PASSTHROUGH,
};

struct pamauth_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;


    enum pamauth_state state;
    bool allow_authfail;
    bool use_child_auth;

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
    int err;
    int rv;

    pamauth_lock(sfilter);

    if (sfilter->pending_err) {
	rv = sfilter->pending_err;
	goto exit;
    }
    if (!sfilter->got_msg) {
	rv = GE_INPROGRESS;
	goto exit;
    }

    switch (sfilter->state) {
    case PAMAUTH_PROMPT:
	sfilter->write_buf_len = 0; /* TODO */
	sfilter->read_buf_len = 0;
	pamauth_write_str(sfilter, "Enter password: ");
	sfilter->state = PAMAUTH_PASSWORD;
	rv = GE_INPROGRESS;
	break;

    case PAMAUTH_PASSWORD:
	if (strcmp(sfilter->read_buf, "harhar") == 0) {
	    sfilter->state = PAMAUTH_PASSTHROUGH;
	    rv = 0;
	} else {
	    sfilter->read_buf_len = 0;
	    pamauth_write_str(sfilter, "Enter password: ");
	    rv = GE_INPROGRESS;
	}
	break;

    default:
	assert(false);
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
    int err = 0;
    unsigned char *obuf = buf;
    unsigned char *nl;
    gensiods chunkLen;

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

    nl = memchr(buf, '\n', buflen);
    if (!nl) {
	/* No newline found. Just copy into our receive buffer if it fits */

	/* TODO: Check overflow? */
	if (sfilter->read_buf_len + buflen > GENSIO_PAMAUTH_DATA_SIZE) {
	    sfilter->pending_err = GE_NOMEM;
	    goto out_unlock;
	}

	memcpy(sfilter->read_buf + sfilter->read_buf_len, buf, buflen);
	sfilter->read_buf_len += buflen;
	buf += buflen;
	goto out_unlock;
    }

    chunkLen = nl - buf + 1;

    /* TODO: Check overflow? */
    if (sfilter->read_buf_len + chunkLen > GENSIO_PAMAUTH_DATA_SIZE) {
	sfilter->pending_err = GE_NOMEM;
	goto out_unlock;
    }

    memcpy(sfilter->read_buf + sfilter->read_buf_len, buf, chunkLen);
    sfilter->read_buf_len += chunkLen;
    sfilter->read_buf[sfilter->read_buf_len - 1] = '\0';
    buf += chunkLen;

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

int
gensio_pamauth_filter_alloc(struct gensio_pamauth_filter_data *data,
			    struct gensio_filter **rfilter)
{
    struct gensio_os_funcs *o = data->o;
    struct gensio_filter *filter;
    struct pamauth_filter *sfilter;
    int rv;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return GE_NOMEM;

    sfilter->o = o;
    sfilter->allow_authfail = data->allow_authfail;
    sfilter->use_child_auth = data->use_child_auth;

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    sfilter->state = PAMAUTH_PROMPT;
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

    *rfilter = sfilter->filter;
    return 0;

 out_nomem:
    rv = GE_NOMEM;
 out_err:
    sfilter_free(sfilter);
    return rv;
}
