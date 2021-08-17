// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <stdlib.h>

#include "resmon.h"

struct resmon_back {
	const struct resmon_back_cls *cls;
};

struct resmon_back_cls {
	struct resmon_back *(*init)(void);
	void (*fini)(struct resmon_back *back);

	int (*get_capacity)(struct resmon_back *back, uint64_t *capacity,
			    char **error);
};

struct resmon_back *resmon_back_init(const struct resmon_back_cls *cls)
{
	return cls->init();
}

void resmon_back_fini(struct resmon_back *back)
{
	return back->cls->fini(back);
}

int resmon_back_get_capacity(struct resmon_back *back, uint64_t *capacity,
			     char **error)
{
	return back->cls->get_capacity(back, capacity, error);
}

struct resmon_back_mock {
	struct resmon_back base;
};

static struct resmon_back *resmon_back_mock_init(void)
{
	struct resmon_back_mock *back;

	back = malloc(sizeof(*back));
	if (back == NULL)
		return NULL;

	*back = (struct resmon_back_mock) {
		.base.cls = &resmon_back_cls_mock,
	};

	return &back->base;
}

static void resmon_back_mock_fini(struct resmon_back *back)
{
	free(back);
}

static int resmon_back_mock_get_capacity(struct resmon_back *back,
					 uint64_t *capacity,
					 char **error)
{
	*capacity = 10000;
	return 0;
}

const struct resmon_back_cls resmon_back_cls_mock = {
	.init = resmon_back_mock_init,
	.fini = resmon_back_mock_fini,
	.get_capacity = resmon_back_mock_get_capacity,
};
