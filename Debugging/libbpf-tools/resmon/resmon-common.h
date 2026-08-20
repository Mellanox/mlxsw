/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Resmon-common has artifacts common to BPF and userspace programs. */

static inline _Bool resmon_reg_supported(unsigned short reg_id)
{
	switch (reg_id)
	case 0x8013: /* MLXSW_REG_RALUE_ID */
	case 0x3006: /* MLXSW_REG_PTAR_ID */
	case 0x3027: /* MLXSW_REG_PTCE3_ID */
	case 0x300F: /* MLXSW_REG_PEFA_ID */
	case 0x3804: /* MLXSW_REG_IEDR_ID */
	case 0x8014: /* MLXSW_REG_RAUHT_ID */
	case 0x8008: /* MLXSW_REG_RATR_ID */
	case 0x200A: /* MLXSW_REG_SFD_ID */
	case 0x2013: /* MLXSW_REG_SFDF_ID */
	case 0x201C: /* MLXSW_REG_SVFA_ID */
	case 0x8021: /* MLXSW_REG_RIPS_ID */
	case 0x201F: /* MLXSW_REG_SFMR_ID */
		return 1;

	return 0;
}
