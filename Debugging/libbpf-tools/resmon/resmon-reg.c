// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "resmon.h"

#define RESMON_REG_REGISTERS(X)		\
	X(RALUE)

#define RESMON_REG_REGISTER_AS_ENUM(NAME)	\
	RESMON_REG_REG_ ## NAME,
#define RESMON_REG_REGISTER_AS_REGMASK(NAME)	\
	RESMON_REG_REGMASK_ ## NAME = (1 << RESMON_REG_REG_ ## NAME),

enum {
	RESMON_REG_REGISTERS(RESMON_REG_REGISTER_AS_ENUM)
};

enum {
	RESMON_REG_REGISTERS(RESMON_REG_REGISTER_AS_REGMASK)
};
#undef RESMON_REG_REGISTER_AS_ENUM
#undef RESMON_REG_REGISTER_AS_REGMASK

#define RESMON_REG_LPM_IPV4_REGMASK	RESMON_REG_REGMASK_RALUE
#define RESMON_REG_LPM_IPV6_REGMASK	RESMON_REG_REGMASK_RALUE

#define RESMON_REG_RSRC_AS_REGMASK(NAME, DESCRIPTION)		\
	[RESMON_RSRC_ ## NAME] = RESMON_REG_ ## NAME ## _REGMASK,

static const unsigned int resmon_reg_resource_regmask[] = {
	RESMON_RESOURCES(RESMON_REG_RSRC_AS_REGMASK)
};

#undef RESMON_REG_RSRC_AS_REGMASK

struct resmon_reg {
	struct resmon_resources_enabled rsrc_en;
	unsigned int regmask;
};

struct resmon_reg *
resmon_reg_create(struct resmon_resources_enabled rsrc_en)
{
	unsigned int regmask = 0;
	struct resmon_reg *rreg;

	rreg = malloc(sizeof(*rreg));
	if (rreg == NULL)
		return NULL;

	for (int i = 0; i < ARRAY_SIZE(rsrc_en.enabled); i++) {
		if (rsrc_en.enabled[i])
			regmask |= resmon_reg_resource_regmask[i];
	}

	*rreg = (struct resmon_reg) {
		.rsrc_en = rsrc_en,
		.regmask = regmask,
	};
	return rreg;
}

void resmon_reg_destroy(struct resmon_reg *rreg)
{
	free(rreg);
}

typedef struct {
	uint16_t value;
} uint16_be_t;

static inline uint16_t uint16_be_toh(uint16_be_t be)
{
	return be16toh(be.value);
}

struct resmon_reg_emad_tl {
	int type;
	int length;
};

struct resmon_reg_op_tlv {
	uint16_be_t type_len;
	uint8_t status;
	uint8_t resv2;
	uint16_be_t reg_id;
	uint8_t r_method;
	uint8_t resv3;
	uint64_t tid;
};

struct resmon_reg_reg_tlv_head {
	uint16_be_t type_len;
	uint16_t reserved;
};

struct resmon_reg_ralue {
	uint8_t __protocol;
	uint8_t __op;
	uint16_be_t resv1;

#define resmon_reg_ralue_protocol(reg)	((reg)->__protocol & 0x0f)
#define resmon_reg_ralue_op(reg) (((reg)->__op & 0x70) >> 4)

	uint16_be_t __virtual_router;
	uint16_be_t resv2;

#define resmon_reg_ralue_virtual_router(reg) \
	(uint16_be_toh((reg)->__virtual_router))

	uint16_be_t resv3;
	uint8_t resv4;
	uint8_t prefix_len;

	union {
		uint8_t dip6[16];
		struct {
			uint8_t resv5[12];
			uint8_t dip4[4];
		};
	};
};

static struct resmon_reg_emad_tl
resmon_reg_emad_decode_tl(uint16_be_t type_len_be)
{
	uint16_t type_len = uint16_be_toh(type_len_be);

	return (struct resmon_reg_emad_tl){
		.type = type_len >> 11,
		.length = type_len & 0x7ff,
	};
}

#define RESMON_REG_PULL(size, payload, payload_len)			\
	({								\
		if (payload_len < size)					\
			goto oob;					\
		__typeof(payload) __ret = payload;			\
		payload += size;					\
		payload_len -= size;					\
		(const void *) __ret;					\
	})

#define RESMON_REG_READ(size, payload, payload_len)			\
	({								\
		__typeof(payload) __payload = payload;			\
		__typeof(payload_len) __payload_len = payload_len;	\
		RESMON_REG_PULL(size, __payload, __payload_len);	\
	})

static void resmon_reg_err_payload_truncated(char **error)
{
	resmon_fmterr(error, "EMAD malformed: Payload truncated");
}

static int resmon_reg_insert_rc(int rc, char **error)
{
	if (rc != 0) {
		resmon_fmterr(error, "Insert failed");
		return -1;
	}
	return 0;
}

static int resmon_reg_delete_rc(int rc, char **error)
{
	if (rc != 0) {
		resmon_fmterr(error, "Delete failed");
		return -1;
	}
	return 0;
}

static int
resmon_reg_handle_ralue(struct resmon_stat *stat, struct resmon_reg *rreg,
			const uint8_t *payload, size_t payload_len,
			char **error)
{
	enum mlxsw_reg_ralxx_protocol protocol;
	const struct resmon_reg_ralue *reg;
	struct resmon_stat_kvd_alloc kvda;
	struct resmon_stat_dip dip = {};
	uint16_t virtual_router;
	uint8_t prefix_len;
	bool ipv6;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	protocol = resmon_reg_ralue_protocol(reg);
	prefix_len = reg->prefix_len;
	virtual_router = resmon_reg_ralue_virtual_router(reg);

	ipv6 = protocol == MLXSW_REG_RALXX_PROTOCOL_IPV6;

	if ((ipv6 && !rreg->rsrc_en.enabled[RESMON_RSRC_LPM_IPV6]) ||
	    (!ipv6 && !rreg->rsrc_en.enabled[RESMON_RSRC_LPM_IPV4]))
		return 0;

	if (ipv6)
		memcpy(dip.dip, reg->dip6, sizeof(reg->dip6));
	else
		memcpy(dip.dip, reg->dip4, sizeof(reg->dip4));

	if (resmon_reg_ralue_op(reg) == MLXSW_REG_RALUE_OP_WRITE_DELETE) {
		rc = resmon_stat_ralue_delete(stat, protocol, prefix_len,
					      virtual_router, dip);
		return resmon_reg_delete_rc(rc, error);
	}

	kvda = (struct resmon_stat_kvd_alloc) {
		.slots = prefix_len <= 64 ? 1 : 2,
		.resource = ipv6 ? RESMON_RSRC_LPM_IPV6
				 : RESMON_RSRC_LPM_IPV4,
	};
	rc = resmon_stat_ralue_update(stat, protocol, prefix_len,
				      virtual_router, dip, kvda);
	return resmon_reg_insert_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static unsigned int resmon_reg_register_as_regmask(uint16_t reg_id)
{
#define RESMON_REG_REGISTER_AS_REGMASK_CASE(NAME)		\
		case MLXSW_REG_ ## NAME ## _ID:			\
			return RESMON_REG_REGMASK_ ## NAME;

	switch (reg_id) {
	RESMON_REG_REGISTERS(RESMON_REG_REGISTER_AS_REGMASK_CASE)
	};
	assert(false);
	abort();

#undef RESMON_REG_REGISTER_AS_REGMASK_CASE
}

static bool
resmon_reg_should_handle(const struct resmon_reg *rreg, uint16_t reg_id)
{
	return (rreg->regmask & resmon_reg_register_as_regmask(reg_id)) != 0;
}

int resmon_reg_process_emad(struct resmon_reg *rreg,
			    struct resmon_stat *stat,
			    const uint8_t *buf, size_t len, char **error)
{
	const struct resmon_reg_reg_tlv_head *reg_tlv;
	const struct resmon_reg_op_tlv *op_tlv;
	struct resmon_reg_emad_tl tl;
	uint16_t reg_id;

	op_tlv = RESMON_REG_READ(sizeof(*op_tlv), buf, len);
	tl = resmon_reg_emad_decode_tl(op_tlv->type_len);

	RESMON_REG_PULL(tl.length * 4, buf, len);
	reg_tlv = RESMON_REG_READ(sizeof(*reg_tlv), buf, len);
	tl = resmon_reg_emad_decode_tl(reg_tlv->type_len);

	/* Skip over the TLV if it is in fact a STRING TLV. */
	if (tl.type == MLXSW_EMAD_TLV_TYPE_STRING) {
		RESMON_REG_PULL(tl.length * 4, buf, len);
		reg_tlv = RESMON_REG_READ(sizeof(*reg_tlv), buf, len);
		tl = resmon_reg_emad_decode_tl(reg_tlv->type_len);
	}

	if (tl.type != MLXSW_EMAD_TLV_TYPE_REG) {
		resmon_fmterr(error, "EMAD malformed: No register");
		return -1;
	}

	/* Get to the register payload. */
	RESMON_REG_PULL(sizeof(*reg_tlv), buf, len);

	reg_id = uint16_be_toh(op_tlv->reg_id);

	if (!resmon_reg_should_handle(rreg, reg_id))
		return 0;

	switch (reg_id) {
	case MLXSW_REG_RALUE_ID:
		return resmon_reg_handle_ralue(stat, rreg, buf, len, error);
	}

	resmon_fmterr(error, "EMAD malformed: Unknown register");
	return -1;

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}
