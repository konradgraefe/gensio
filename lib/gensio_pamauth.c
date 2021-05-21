#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_acc_gensio.h>

#include "gensio_filter_pamauth.h"

int
pamauth_gensio_alloc(struct gensio *child, const char *const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **net)
{
    return GE_NOTSUP; /* TODO */
}

int
str_to_pamauth_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = pamauth_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct pamauthna_data {
    struct gensio_accepter *acc;
    struct gensio_pamauth_filter_data *data;
    struct gensio_os_funcs *o;
};

static void
pamauthna_free(void *acc_data)
{
    struct pamauthna_data *nadata = acc_data;

    gensio_pamauth_filter_config_free(nadata->data);
    nadata->o->free(nadata->o, nadata);
}

static int
pamauthna_alloc_gensio(void *acc_data, const char * const *iargs,
			struct gensio *child, struct gensio **rio)
{
    struct pamauthna_data *nadata = acc_data;

    return pamauth_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
pamauthna_new_child(void *acc_data, void **finish_data,
		     struct gensio_filter **filter)
{
    struct pamauthna_data *nadata = acc_data;

    return gensio_pamauth_filter_alloc(nadata->data, filter);
}

static int
pamauthna_gensio_event(struct gensio *io, void *user_data, int event, int err,
			unsigned char *buf, gensiods *buflen,
			const char *const *auxdata)
{
    struct pamauthna_data *nadata = user_data;
    struct gensio_acc_password_verify_data pwvfy;
    struct gensio_acc_postcert_verify_data postvfy;
    int rv;

    switch (event) {
    case GENSIO_EVENT_AUTH_BEGIN:
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_AUTH_BEGIN, io);

    case GENSIO_EVENT_PRECERT_VERIFY:
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_PRECERT_VERIFY, io);

    case GENSIO_EVENT_POSTCERT_VERIFY:
	postvfy.io = io;
	postvfy.err = err;
	postvfy.errstr = auxdata ? auxdata[0] : NULL;
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_POSTCERT_VERIFY,
			     &postvfy);

    case GENSIO_EVENT_PASSWORD_VERIFY:
	pwvfy.io = io;
	pwvfy.password = (char *) buf;
	pwvfy.password_len = *buflen;
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_PASSWORD_VERIFY,
			     &pwvfy);

    case GENSIO_EVENT_REQUEST_PASSWORD:
	pwvfy.io = io;
	pwvfy.password = (char *) buf;
	pwvfy.password_len = *buflen;
	rv = gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_REQUEST_PASSWORD,
			   &pwvfy);
	if (!rv)
	    *buflen = pwvfy.password_len;
	return rv;

    default:
	return GE_NOTSUP;
    }
}

static int
pamauthna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_callback(io, pamauthna_gensio_event, acc_data);
    return 0;
}

static int
gensio_gensio_acc_pamauth_cb(void *acc_data, int op, void *data1, void *data2,
			     void *data3, const void *data4)
{
    struct pamauthna_data *nadata = acc_data;

    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return pamauthna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return pamauthna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return pamauthna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	pamauthna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
pamauth_gensio_accepter_alloc(struct gensio_accepter *child,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb, void *user_data,
			      struct gensio_accepter **accepter)
{
    struct pamauthna_data *nadata;
    int err;

    if (!gensio_acc_is_reliable(child))
	/* Cowardly refusing to run over an unreliable connection. */
	return GE_NOTSUP;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    err = gensio_pamauth_filter_config(o, args, &nadata->data);
    if (err) {
        o->free(o, nadata);
        return err;
    }

    nadata->o = o;

    err = gensio_gensio_accepter_alloc(child, o, "pamauth", cb, user_data,
				       gensio_gensio_acc_pamauth_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_packet(nadata->acc, gensio_acc_is_packet(child));
    gensio_acc_set_is_reliable(nadata->acc, gensio_acc_is_reliable(child));
    *accepter = nadata->acc;

    return 0;

 out_err:
    pamauthna_free(nadata);
    return err;
}

int
str_to_pamauth_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = pamauth_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}
