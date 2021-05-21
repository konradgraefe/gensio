#pragma once

#include <gensio/gensio_base.h>

struct gensio_pamauth_filter_data;

int gensio_pamauth_filter_config(struct gensio_os_funcs *o,
				 const char * const args[],
				 struct gensio_pamauth_filter_data **rdata);

void
gensio_pamauth_filter_config_free(struct gensio_pamauth_filter_data *data);

bool gensio_pamauth_filter_config_allow_unencrypted(
	     struct gensio_pamauth_filter_data *data);

int gensio_pamauth_filter_alloc(struct gensio_pamauth_filter_data *data,
				struct gensio_filter **rfilter);
