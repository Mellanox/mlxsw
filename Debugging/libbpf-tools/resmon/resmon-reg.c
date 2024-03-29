// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "resmon.h"

#define RESMON_REG_REGISTERS(X)		\
	X(RALUE)			\
	X(PTAR)				\
	X(PTCE3)			\
	X(PEFA)				\
	X(IEDR)				\
	X(RAUHT)			\
	X(RATR)				\
	X(SFD)				\
	X(SFDF)				\
	X(SVFA)				\
	X(RIPS)				\
	X(SFMR)				\
	/**/

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
#define RESMON_REG_ATCAM_REGMASK	(RESMON_REG_REGMASK_PTAR |	\
					 RESMON_REG_REGMASK_PTCE3)
#define RESMON_REG_ACTSET_REGMASK	(RESMON_REG_REGMASK_PTCE3 |	\
					 RESMON_REG_REGMASK_PEFA |	\
					 RESMON_REG_REGMASK_IEDR)
#define RESMON_REG_HOSTTAB_IPV4_REGMASK	RESMON_REG_REGMASK_RAUHT
#define RESMON_REG_HOSTTAB_IPV6_REGMASK	RESMON_REG_REGMASK_RAUHT
#define RESMON_REG_ADJTAB_REGMASK	(RESMON_REG_REGMASK_RATR |	\
					 RESMON_REG_REGMASK_IEDR)
#define RESMON_REG_FDB_REGMASK		(RESMON_REG_REGMASK_SFD |	\
					 RESMON_REG_REGMASK_SFDF)
#define RESMON_REG_VID2FID_REGMASK	RESMON_REG_REGMASK_SVFA
#define RESMON_REG_RQ_VID2FID_REGMASK	RESMON_REG_REGMASK_SVFA
#define RESMON_REG_VNI2FID_REGMASK	RESMON_REG_REGMASK_SVFA
#define RESMON_REG_IPV6ADDR_REGMASK	(RESMON_REG_REGMASK_RIPS |	\
					 RESMON_REG_REGMASK_IEDR)
#define RESMON_REG_FID2FID_REGMASK	RESMON_REG_REGMASK_SFMR

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

typedef struct {
	uint32_t value;
} uint32_be_t;

static inline uint16_t uint16_be_toh(uint16_be_t be)
{
	return be16toh(be.value);
}

static inline uint32_t uint32_be_toh(uint32_be_t be)
{
	return be32toh(be.value);
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

struct resmon_reg_ptar {
	uint8_t __op_e;
	uint8_t action_set_type;
	uint8_t resv1;
	uint8_t key_type;

#define resmon_reg_ptar_op(reg) ((reg)->__op_e >> 4)

	uint16_be_t resv2;
	uint16_be_t __region_size;

	uint16_be_t resv3;
	uint16_be_t __region_id;

	uint16_be_t resv4;
	uint8_t __dup_opt;
	uint8_t __packet_rate;

	uint8_t tcam_region_info[16];
	uint8_t flexible_keys[16];
};

struct resmon_reg_ptce3 {
	uint8_t __v_a;
	uint8_t __op;
	uint8_t resv1;
	uint8_t __dup;

#define resmon_reg_ptce3_v(reg) ((reg)->__v_a >> 7)
#define resmon_reg_ptce3_op(reg) (((reg)->__op >> 4) & 7)

	uint32_be_t __priority;

	uint32_be_t resv2;

	uint32_be_t resv3;

	uint8_t tcam_region_info[16];

	uint8_t flex2_key_blocks[96];

	uint16_be_t resv4;
	uint8_t resv5;
	uint8_t __erp_id;

#define resmon_reg_ptce3_erp_id(reg) ((reg)->__erp_id & 0xf)

	uint16_be_t resv6;
	uint16_be_t __delta_start;

#define resmon_reg_ptce3_delta_start(reg) \
	(uint16_be_toh((reg)->__delta_start) & 0x3ff)

	uint8_t resv7;
	uint8_t delta_mask;
	uint8_t resv8;
	uint8_t delta_value;
};

struct resmon_reg_pefa {
	uint32_be_t __pind_index;

#define resmon_reg_pefa_index(reg) \
	(uint32_be_toh((reg)->__pind_index) & 0xffffff)
};

struct resmon_reg_iedr_record {
	uint8_t type;
	uint8_t resv1;
	uint16_be_t __size;

#define resmon_reg_iedr_record_size(rec) (uint16_be_toh((rec)->__size))

	uint32_be_t __index_start;

#define resmon_reg_iedr_record_index_start(rec) \
	(uint32_be_toh((rec)->__index_start) & 0xffffff)
};

struct resmon_reg_iedr {
	uint8_t __bg;
	uint8_t resv1;
	uint8_t resv2;
	uint8_t num_rec;

	uint32_be_t resv3;

	uint32_be_t resv4;

	uint32_be_t resv5;

	struct resmon_reg_iedr_record records[64];
};

struct resmon_reg_rauht {
	uint8_t __type;
	uint8_t __op;
	uint16_be_t __rif;

#define resmon_reg_rauht_type(reg) ((reg)->__type & 0x03)
#define resmon_reg_rauht_op(reg) (((reg)->__op & 0x70) >> 4)
#define resmon_reg_rauht_rif(reg) (uint16_be_toh((reg)->__rif) & 0x70)

	uint32_be_t resv1;
	uint32_be_t resv2;
	uint32_be_t resv3;

	union {
		uint8_t dip6[16];
		struct {
			uint8_t resv4[12];
			uint8_t dip4[4];
		};
	};
};

struct resmon_reg_ratr {
	uint8_t __opcode_v;
	uint8_t __a;
	uint16_be_t __size;

#define resmon_reg_ratr_opcode(reg) (((reg)->__opcode_v >> 4) & 0xf)

	uint8_t __type;
	uint8_t __table;
	uint16_be_t __adj_index_low;

#define resmon_reg_ratr_adj_index_low(reg) uint16_be_toh((reg)->__adj_index_low)

	uint16_be_t resv1;
	uint16_be_t __egress_router_interface;

	uint8_t __trap_action;
	uint8_t adj_index_high;

#define resmon_reg_ratr_adj_index(reg) \
	(((reg)->adj_index_high << (uint32_t)16) | \
	 resmon_reg_ratr_adj_index_low(reg))
};

struct resmon_reg_sfd_record {
	uint8_t swid;
	uint8_t __type_policy_a;

#define resmon_reg_sfd_record_type(rec) (((rec)->__type_policy_a & 0xf0) >> 4)

	uint8_t mac[6];
	uint16_be_t resv2;
	uint16_be_t __fid_vid;

#define resmon_reg_sfd_record_fid_vid(rec) (uint16_be_toh((rec)->__fid_vid))

	uint16_be_t resv3;
	uint16_be_t __port_lag_mid;

#define resmon_reg_sfd_record_system_port(rec) \
		(uint16_be_toh((rec)->__port_lag_mid))
#define resmon_reg_sfd_record_lag_id(rec) \
		(uint16_be_toh((rec)->__port_lag_mid) & 0x03ff)
#define resmon_reg_sfd_record_mid(rec) \
		(uint16_be_toh((rec)->__port_lag_mid))

	uint16_be_t resv4;
	uint16_be_t __tunnel_port;

#define resmon_reg_sfd_record_tunnel_port(rec) \
		(uint16_be_toh((rec)->__tunnel_port) & 0xf)

	uint32_be_t resv5;
	uint32_be_t resv6;
	uint32_be_t resv7;
};

struct resmon_reg_sfd {
	uint8_t swid;
	uint8_t __rec_type;

#define resmon_reg_sfd_rec_type(reg) (((reg)->__rec_type & 0x10) >> 4)

	uint16_be_t resv1;
	uint32_be_t __op_record_locator;

#define resmon_reg_sfd_op(reg) (uint32_be_toh((reg)->__op_record_locator) >> 30)

	uint16_be_t resv2;
	uint8_t resv3;
	uint8_t num_rec;
	uint32_be_t resv4;

	struct resmon_reg_sfd_record records[32];
};

struct resmon_reg_sfdf_param_flush_fid {
	uint32_t resv1;
	uint16_t resv2;
	uint16_be_t fid;
#define resmon_reg_sfdf_param_flush_fid(reg) (uint16_be_toh((reg)->flush_fid.fid))
};

struct resmon_reg_sfdf_param_flush_port {
	uint32_t resv1;
	uint16_t resv2;
	uint16_be_t system_port;
#define resmon_reg_sfdf_param_flush_port(reg) \
		(uint16_be_toh((reg)->flush_port.system_port))
};

struct resmon_reg_sfdf_param_flush_port_fid {
	uint16_t resv1;
	uint16_be_t system_port;
#define resmon_reg_sfdf_param_flush_port_fid_port(reg) \
		(uint16_be_toh((reg)->flush_port_fid.system_port))
	uint16_t resv2;
	uint16_be_t fid;
#define resmon_reg_sfdf_param_flush_port_fid_fid(reg) \
		(uint16_be_toh((reg)->flush_port_fid.fid))
};

struct resmon_reg_sfdf_param_flush_lag {
	uint32_t resv1;
	uint16_t resv2;
	uint16_be_t lag_id;
#define resmon_reg_sfdf_param_flush_lag(reg) \
		(uint16_be_toh((reg)->flush_lag.lag_id) & 0x3ff)
};

struct resmon_reg_sfdf_param_flush_lag_fid {
	uint16_t resv1;
	uint16_be_t lag_id;
#define resmon_reg_sfdf_param_flush_lag_fid_lag_id(reg) \
		(uint16_be_toh((reg)->flush_lag_fid.lag_id) & 0x3ff)
	uint16_t resv2;
	uint16_be_t fid;
#define resmon_reg_sfdf_param_flush_lag_fid_fid(reg) \
		(uint16_be_toh((reg)->flush_lag_fid.fid))
};

struct resmon_reg_sfdf_param_flush_nve_fid {
	uint32_t resv1;
	uint16_t resv2;
	uint16_be_t fid;
#define resmon_reg_sfdf_param_flush_nve_fid(reg) \
		(uint16_be_toh((reg)->flush_nve_fid.fid))
};

struct resmon_reg_sfdf {
	uint8_t swid;
	uint8_t resv1;
	uint16_t resv2;
	uint8_t __flushtype_imdu_iut_st;

#define resmon_reg_sfdf_flush_type(reg) \
		(((reg)->__flushtype_imdu_iut_st & 0xf0) >> 4)

	uint8_t resv3;
	uint16_t resv4;

	union {
		uint64_t resv5; /* FLUSH_PER_SWID, FLUSH_PER_NVE */
		struct resmon_reg_sfdf_param_flush_fid flush_fid;
		struct resmon_reg_sfdf_param_flush_port flush_port;
		struct resmon_reg_sfdf_param_flush_port_fid flush_port_fid;
		struct resmon_reg_sfdf_param_flush_lag flush_lag;
		struct resmon_reg_sfdf_param_flush_lag_fid flush_lag_fid;
		struct resmon_reg_sfdf_param_flush_nve_fid flush_nve_fid;
	};
};

struct resmon_reg_svfa {
	uint8_t __swid;
	uint8_t __local_port;
	uint8_t __local_port_msb_mapping_table;
	uint8_t __tport_v;

#define resmon_reg_svfa_mapping_table(reg) \
	((reg)->__local_port_msb_mapping_table & 0x07)
#define resmon_reg_svfa_local_port_msb(reg) \
	((reg)->__local_port_msb_mapping_table >> 4)
#define resmon_reg_svfa_local_port(reg)\
	((resmon_reg_svfa_local_port_msb(reg) << (uint16_t)8) | \
	 (reg)->__local_port)
#define resmon_reg_svfa_v(reg) ((reg)->__tport_v & 1)

	uint16_be_t __fid;
	uint16_be_t __vid;

#define resmon_reg_svfa_vid(reg) (uint16_be_toh((reg)->__vid) & 0x0fff)

	uint32_be_t __counter_set_type_index;

	uint8_t __trap_action;
	uint8_t resv1;
	uint16_be_t __trap_id;

	uint32_be_t __vni;

#define resmon_reg_svfa_vni(reg) (uint32_be_toh((reg)->__vni) & 0x00ffffff)
};

struct resmon_reg_rips {
	uint32_be_t __index;

#define resmon_reg_rips_index(reg) ((uint32_be_toh((reg)->__index) & 0xffffff))

	uint8_t __dip6[16];
};

struct resmon_reg_sfmr {
	uint8_t __op;

#define resmon_reg_sfmr_op(reg) ((reg)->__op & 0x0f)

	uint8_t resv1;
	uint16_be_t __fid;

#define resmon_reg_sfmr_fid(reg) uint16_be_toh((reg)->__fid)
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

static struct resmon_stat_kvd_alloc
resmon_reg_ptar_get_kvd_alloc(const struct resmon_reg_ptar *reg)
{
	size_t nkeys = 0;

	for (size_t i = 0; i < sizeof(reg->flexible_keys); i++)
		if (reg->flexible_keys[i])
			nkeys++;

	return (struct resmon_stat_kvd_alloc) {
		.slots = nkeys >= 12 ? 4 :
			 nkeys >= 4  ? 2 : 1,
		.resource = RESMON_RSRC_ATCAM,
	};
}

static int resmon_reg_handle_ptar(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_kvd_alloc kvd_alloc;
	const struct resmon_reg_ptar *reg;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	switch (reg->key_type) {
	case MLXSW_REG_PTAR_KEY_TYPE_FLEX:
	case MLXSW_REG_PTAR_KEY_TYPE_FLEX2:
		break;
	default:
		return 0;
	}

	memcpy(tcam_region_info.tcam_region_info, reg->tcam_region_info,
	       sizeof(tcam_region_info.tcam_region_info));

	switch (resmon_reg_ptar_op(reg)) {
	case MLXSW_REG_PTAR_OP_RESIZE:
	case MLXSW_REG_PTAR_OP_TEST:
	default:
		return 0;
	case MLXSW_REG_PTAR_OP_ALLOC:
		kvd_alloc = resmon_reg_ptar_get_kvd_alloc(reg);
		rc = resmon_stat_ptar_alloc(stat, tcam_region_info, kvd_alloc);
		return resmon_reg_insert_rc(rc, error);
	case MLXSW_REG_PTAR_OP_FREE:
		rc = resmon_stat_ptar_free(stat, tcam_region_info);
		return resmon_reg_delete_rc(rc, error);
	}

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_ptce3(struct resmon_stat *stat,
				   const uint8_t *payload, size_t payload_len,
				   char **error)
{
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_flex2_key_blocks key_blocks;
	struct resmon_stat_kvd_alloc kvd_alloc;
	const struct resmon_reg_ptce3 *reg;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	switch (resmon_reg_ptce3_op(reg)) {
	case MLXSW_REG_PTCE3_OP_WRITE_WRITE:
	case MLXSW_REG_PTCE3_OP_WRITE_UPDATE:
		break;
	default:
		return 0;
	}

	memcpy(tcam_region_info.tcam_region_info, reg->tcam_region_info,
	       sizeof(tcam_region_info.tcam_region_info));
	memcpy(key_blocks.flex2_key_blocks, reg->flex2_key_blocks,
	       sizeof(key_blocks.flex2_key_blocks));

	if (resmon_reg_ptce3_v(reg)) {
		rc = resmon_stat_ptar_get(stat, tcam_region_info, &kvd_alloc);
		if (rc != 0)
			return resmon_reg_insert_rc(rc, error);

		rc = resmon_stat_ptce3_alloc(stat, tcam_region_info,
					     &key_blocks, reg->delta_mask,
					     reg->delta_value,
					     resmon_reg_ptce3_delta_start(reg),
					     resmon_reg_ptce3_erp_id(reg),
					     kvd_alloc);
		return resmon_reg_insert_rc(rc, error);
	}

	rc = resmon_stat_ptce3_free(stat, tcam_region_info,
				    &key_blocks, reg->delta_mask,
				    reg->delta_value,
				    resmon_reg_ptce3_delta_start(reg),
				    resmon_reg_ptce3_erp_id(reg));
	return resmon_reg_delete_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_pefa(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	struct resmon_stat_kvd_alloc kvd_alloc = {
		.slots = 1,
		.resource = RESMON_RSRC_ACTSET,
	};
	const struct resmon_reg_pefa *reg;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	rc = resmon_stat_kvdl_alloc(stat, resmon_reg_pefa_index(reg),
				    kvd_alloc);
	return resmon_reg_insert_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_iedr_record(struct resmon_stat *stat,
					 struct resmon_reg_iedr_record record)
{
	enum resmon_resource resource;
	uint32_t index;
	uint32_t size;

	switch (record.type) {
	case 0x21:
		resource = RESMON_RSRC_ADJTAB;
		break;
	case 0x23:
		resource = RESMON_RSRC_ACTSET;
		break;
	case 0x28:
		resource = RESMON_RSRC_IPV6ADDR;
		break;
	default:
		return 0;
	}

	index = resmon_reg_iedr_record_index_start(&record);
	size = resmon_reg_iedr_record_size(&record);
	return resmon_stat_kvdl_free(stat, index,
				     (struct resmon_stat_kvd_alloc) {
						.slots = size,
						.resource = resource,
				     });
}

static int resmon_reg_handle_iedr(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	const struct resmon_reg_iedr *reg;
	int rc = 0;
	int rc_1;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	if (reg->num_rec > ARRAY_SIZE(reg->records)) {
		resmon_fmterr(error, "EMAD malformed: Inconsistent register");
		return -1;
	}

	for (size_t i = 0; i < reg->num_rec; i++) {
		rc_1 = resmon_reg_handle_iedr_record(stat, reg->records[i]);
		if (rc_1 != 0)
			rc = rc_1;
	}

	return resmon_reg_delete_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_rauht(struct resmon_stat *stat,
				   const uint8_t *payload, size_t payload_len,
				   char **error)
{
	enum mlxsw_reg_ralxx_protocol protocol;
	const struct resmon_reg_rauht *reg;
	struct resmon_stat_kvd_alloc kvda;
	struct resmon_stat_dip dip = {};
	uint16_t rif;
	bool ipv6;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	protocol = resmon_reg_rauht_type(reg);
	rif = resmon_reg_rauht_rif(reg);

	ipv6 = protocol == MLXSW_REG_RALXX_PROTOCOL_IPV6;
	if (ipv6)
		memcpy(dip.dip, reg->dip6, sizeof(reg->dip6));
	else
		memcpy(dip.dip, reg->dip4, sizeof(reg->dip4));

	if (resmon_reg_rauht_op(reg) == MLXSW_REG_RAUHT_OP_WRITE_DELETE) {
		rc = resmon_stat_rauht_delete(stat, protocol, rif, dip);
		return resmon_reg_delete_rc(rc, error);
	}

	kvda = (struct resmon_stat_kvd_alloc) {
		.slots = ipv6 ? 2 : 1,
		.resource = ipv6 ? RESMON_RSRC_HOSTTAB_IPV6
				 : RESMON_RSRC_HOSTTAB_IPV4,
	};
	rc = resmon_stat_rauht_update(stat, protocol, rif, dip, kvda);
	return resmon_reg_insert_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_ratr(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	const struct resmon_reg_ratr *reg;
	struct resmon_stat_kvd_alloc kvda;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	kvda = (struct resmon_stat_kvd_alloc) {
		.slots = 1,
		.resource = RESMON_RSRC_ADJTAB,
	};

	if (resmon_reg_ratr_opcode(reg) == MLXSW_REG_RATR_OP_WRITE_WRITE_ENTRY) {
		rc = resmon_stat_kvdl_alloc(stat,
					    resmon_reg_ratr_adj_index(reg),
					    kvda);
		return resmon_reg_insert_rc(rc, error);
	}

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_sfd_record(struct resmon_stat *stat,
					struct resmon_reg_sfd_record record,
					enum mlxsw_reg_sfd_rec_type rec_type,
					enum mlxsw_reg_sfd_op op)
{
	enum resmon_stat_sfd_param_type param_type;
	struct resmon_stat_kvd_alloc kvda;
	struct resmon_stat_mac mac = {};
	uint16_t fid, param = 0;
	uint8_t record_type;

	memcpy(mac.mac, &record.mac, sizeof(mac));
	fid = resmon_reg_sfd_record_fid_vid(&record);
	record_type = resmon_reg_sfd_record_type(&record);

	switch (record_type) {
	case MLXSW_REG_SFD_REC_TYPE_UNICAST:
		param = resmon_reg_sfd_record_system_port(&record);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_SYSTEM_PORT;
		break;
	case MLXSW_REG_SFD_REC_TYPE_UNICAST_LAG:
		param = resmon_reg_sfd_record_lag_id(&record);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_LAG;
		break;
	case MLXSW_REG_SFD_REC_TYPE_MULTICAST:
		param = resmon_reg_sfd_record_mid(&record);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_MID;
		break;
	case MLXSW_REG_SFD_REC_TYPE_UNICAST_TUNNEL:
		param = resmon_reg_sfd_record_tunnel_port(&record);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_TUNNEL_PORT;
		break;
	default:
		return 0;
	}

	switch (op) {
	case MLXSW_REG_SFD_OP_WRITE_EDIT:
		kvda = (struct resmon_stat_kvd_alloc) {
			.slots = 1,
			.resource = RESMON_RSRC_FDB,
		};
		return resmon_stat_sfd_update(stat, mac, fid, param_type, param,
					      kvda);
	case MLXSW_REG_SFD_OP_WRITE_REMOVE:
		return resmon_stat_sfd_delete(stat, mac, fid);
	default:
		return 0;
	}

	return 0;
}

static int resmon_reg_handle_sfd(struct resmon_stat *stat,
				 const uint8_t *payload, size_t payload_len,
				 char **error)
{
	const struct resmon_reg_sfd *reg;
	uint8_t rec_type, op;
	int rc = 0;
	int rc_1;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	rec_type = resmon_reg_sfd_rec_type(reg);
	op = resmon_reg_sfd_op(reg);

	if (reg->num_rec > ARRAY_SIZE(reg->records)) {
		resmon_fmterr(error, "EMAD malformed: Inconsistent register");
		return -1;
	}

	for (size_t i = 0; i < reg->num_rec; i++) {
		rc_1 = resmon_reg_handle_sfd_record(stat, reg->records[i],
						    rec_type, op);
		if (rc_1 != 0)
			rc = rc_1;
	}

	if (op == MLXSW_REG_SFD_OP_WRITE_EDIT)
		return resmon_reg_insert_rc(rc, error);

	return resmon_reg_delete_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_sfdf(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	enum resmon_stat_sfd_param_type param_type = 0;
	const struct resmon_reg_sfdf *reg;
	uint8_t flush_type, flags = 0;
	uint16_t fid = 0, param = 0;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	flush_type = resmon_reg_sfdf_flush_type(reg);

	switch (flush_type) {
	case MLXSW_REG_SFDF_FLUSH_PER_FID:
		fid = resmon_reg_sfdf_param_flush_fid(reg);
		flags |= RESMON_STAT_SFD_MATCH_FID;
		break;
	case MLXSW_REG_SFDF_FLUSH_PER_PORT:
		param = resmon_reg_sfdf_param_flush_port(reg);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_SYSTEM_PORT;
		flags |= RESMON_STAT_SFD_MATCH_PARAM;
		flags |= RESMON_STAT_SFD_MATCH_PARAM_TYPE;
		break;
	case MLXSW_REG_SFDF_FLUSH_PER_PORT_AND_FID:
		fid = resmon_reg_sfdf_param_flush_port_fid_fid(reg);
		param = resmon_reg_sfdf_param_flush_port_fid_port(reg);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_SYSTEM_PORT;
		flags |= RESMON_STAT_SFD_MATCH_FID;
		flags |= RESMON_STAT_SFD_MATCH_PARAM;
		flags |= RESMON_STAT_SFD_MATCH_PARAM_TYPE;
		break;
	case MLXSW_REG_SFDF_FLUSH_PER_LAG:
		param = resmon_reg_sfdf_param_flush_lag(reg);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_LAG;
		flags |= RESMON_STAT_SFD_MATCH_PARAM;
		flags |= RESMON_STAT_SFD_MATCH_PARAM_TYPE;
		break;
	case MLXSW_REG_SFDF_FLUSH_PER_LAG_AND_FID:
		fid = resmon_reg_sfdf_param_flush_lag_fid_fid(reg);
		param = resmon_reg_sfdf_param_flush_lag_fid_lag_id(reg);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_LAG;
		flags |= RESMON_STAT_SFD_MATCH_FID;
		flags |= RESMON_STAT_SFD_MATCH_PARAM;
		flags |= RESMON_STAT_SFD_MATCH_PARAM_TYPE;
		break;
	case MLXSW_REG_SFDF_FLUSH_PER_NVE:
		param_type = RESMON_STAT_SFD_PARAM_TYPE_TUNNEL_PORT;
		flags |= RESMON_STAT_SFD_MATCH_PARAM_TYPE;
		break;
	case MLXSW_REG_SFDF_FLUSH_PER_NVE_AND_FID:
		fid = resmon_reg_sfdf_param_flush_nve_fid(reg);
		param_type = RESMON_STAT_SFD_PARAM_TYPE_TUNNEL_PORT;
		flags |= RESMON_STAT_SFD_MATCH_FID;
		flags |= RESMON_STAT_SFD_MATCH_PARAM_TYPE;
		break;
	case MLXSW_REG_SFDF_FLUSH_PER_SWID: /* swid is reserved for Spectrum */
	default:
		return -1;
	}

	return resmon_stat_sfdf_flush(stat, fid, param_type, param, flags);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_svfa(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	enum mlxsw_reg_svfa_mt mapping_table;
	const struct resmon_reg_svfa *reg;
	struct resmon_stat_kvd_alloc kvda;
	enum resmon_resource resource;
	uint16_t local_port = 0;
	uint32_t vid_vni;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	mapping_table = resmon_reg_svfa_mapping_table(reg);

	switch (mapping_table) {
	case MLXSW_REG_SVFA_MT_VID_TO_FID:
		resource = RESMON_RSRC_VID2FID;
		vid_vni = resmon_reg_svfa_vid(reg);
		break;
	case MLXSW_REG_SVFA_MT_PORT_VID_TO_FID:
		resource = RESMON_RSRC_RQ_VID2FID;
		local_port = resmon_reg_svfa_local_port(reg);
		vid_vni = resmon_reg_svfa_vid(reg);
		break;
	case MLXSW_REG_SVFA_MT_VNI_TO_FID:
		resource = RESMON_RSRC_VNI2FID;
		vid_vni = resmon_reg_svfa_vni(reg);
		break;
	default:
		return 0;
	}

	if (!resmon_reg_svfa_v(reg)) {
		rc = resmon_stat_svfa_delete(stat, mapping_table, local_port,
					     vid_vni);
		return resmon_reg_delete_rc(rc, error);
	}

	kvda = (struct resmon_stat_kvd_alloc) {
		.slots = 1,
		.resource = resource,
	};
	rc = resmon_stat_svfa_update(stat, mapping_table, local_port, vid_vni,
				     kvda);
	return resmon_reg_insert_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_rips(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	const struct resmon_reg_rips *reg;
	struct resmon_stat_kvd_alloc kvda;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	kvda = (struct resmon_stat_kvd_alloc) {
		.slots = 1,
		.resource = RESMON_RSRC_IPV6ADDR,
	};

	rc = resmon_stat_kvdl_alloc(stat, resmon_reg_rips_index(reg), kvda);
	return resmon_reg_insert_rc(rc, error);

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}

static int resmon_reg_handle_sfmr(struct resmon_stat *stat,
				  const uint8_t *payload, size_t payload_len,
				  char **error)
{
	struct resmon_stat_kvd_alloc kvda = {
		.slots = 1,
		.resource = RESMON_RSRC_FID2FID,
	};
	const struct resmon_reg_sfmr *reg;
	uint16_t fid;
	int rc;

	reg = RESMON_REG_READ(sizeof(*reg), payload, payload_len);
	fid = resmon_reg_sfmr_fid(reg);

	switch (resmon_reg_sfmr_op(reg)) {
	case MLXSW_REG_SFMR_OP_CREATE_FID:
		rc = resmon_stat_sfmr_update(stat, fid, kvda);
		return resmon_reg_insert_rc(rc, error);
	case MLXSW_REG_SFMR_OP_DESTROY_FID:
		rc = resmon_stat_sfmr_delete(stat, fid);
		return resmon_reg_delete_rc(rc, error);
	default:
		return 0;
	};

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

	while (tl.type != MLXSW_EMAD_TLV_TYPE_REG) {
		RESMON_REG_PULL(tl.length * 4, buf, len);
		reg_tlv = RESMON_REG_READ(sizeof(*reg_tlv), buf, len);
		tl = resmon_reg_emad_decode_tl(reg_tlv->type_len);
	}

	/* Get to the register payload. */
	RESMON_REG_PULL(sizeof(*reg_tlv), buf, len);

	reg_id = uint16_be_toh(op_tlv->reg_id);

	if (!resmon_reg_should_handle(rreg, reg_id))
		return 0;

	switch (reg_id) {
	case MLXSW_REG_RALUE_ID:
		return resmon_reg_handle_ralue(stat, rreg, buf, len, error);
	case MLXSW_REG_PTAR_ID:
		return resmon_reg_handle_ptar(stat, buf, len, error);
	case MLXSW_REG_PTCE3_ID:
		return resmon_reg_handle_ptce3(stat, buf, len, error);
	case MLXSW_REG_PEFA_ID:
		return resmon_reg_handle_pefa(stat, buf, len, error);
	case MLXSW_REG_IEDR_ID:
		return resmon_reg_handle_iedr(stat, buf, len, error);
	case MLXSW_REG_RAUHT_ID:
		return resmon_reg_handle_rauht(stat, buf, len, error);
	case MLXSW_REG_RATR_ID:
		return resmon_reg_handle_ratr(stat, buf, len, error);
	case MLXSW_REG_SFD_ID:
		return resmon_reg_handle_sfd(stat, buf, len, error);
	case MLXSW_REG_SFDF_ID:
		return resmon_reg_handle_sfdf(stat, buf, len, error);
	case MLXSW_REG_SVFA_ID:
		return resmon_reg_handle_svfa(stat, buf, len, error);
	case MLXSW_REG_RIPS_ID:
		return resmon_reg_handle_rips(stat, buf, len, error);
	case MLXSW_REG_SFMR_ID:
		return resmon_reg_handle_sfmr(stat, buf, len, error);
	}

	resmon_fmterr(error, "EMAD malformed: Unknown register");
	return -1;

oob:
	resmon_reg_err_payload_truncated(error);
	return -1;
}
