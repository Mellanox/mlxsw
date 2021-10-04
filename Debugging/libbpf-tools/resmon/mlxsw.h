/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */

/* EMAD TLV Types */
enum {
	MLXSW_EMAD_TLV_TYPE_END,
	MLXSW_EMAD_TLV_TYPE_OP,
	MLXSW_EMAD_TLV_TYPE_STRING,
	MLXSW_EMAD_TLV_TYPE_REG,
};

enum mlxsw_reg_ralxx_protocol {
	MLXSW_REG_RALXX_PROTOCOL_IPV4,
	MLXSW_REG_RALXX_PROTOCOL_IPV6,
};

#define MLXSW_REG_RALUE_ID 0x8013

enum mlxsw_reg_ralue_op {
	/* Read operation. If entry doesn't exist, the operation fails. */
	MLXSW_REG_RALUE_OP_QUERY_READ = 0,
	/* Clear on read operation. Used to read entry and
	 * clear Activity bit.
	 */
	MLXSW_REG_RALUE_OP_QUERY_CLEAR = 1,
	/* Write operation. Used to write a new entry to the table. All RW
	 * fields are written for new entry. Activity bit is set
	 * for new entries.
	 */
	MLXSW_REG_RALUE_OP_WRITE_WRITE = 0,
	/* Update operation. Used to update an existing route entry and
	 * only update the RW fields that are detailed in the field
	 * op_u_mask. If entry doesn't exist, the operation fails.
	 */
	MLXSW_REG_RALUE_OP_WRITE_UPDATE = 1,
	/* Clear activity. The Activity bit (the field a) is cleared
	 * for the entry.
	 */
	MLXSW_REG_RALUE_OP_WRITE_CLEAR = 2,
	/* Delete operation. Used to delete an existing entry. If entry
	 * doesn't exist, the operation fails.
	 */
	MLXSW_REG_RALUE_OP_WRITE_DELETE = 3,
};

#define MLXSW_REG_PTAR_ID 0x3006

enum mlxsw_reg_ptar_op {
	/* allocate a TCAM region */
	MLXSW_REG_PTAR_OP_ALLOC,
	/* resize a TCAM region */
	MLXSW_REG_PTAR_OP_RESIZE,
	/* deallocate TCAM region */
	MLXSW_REG_PTAR_OP_FREE,
	/* test allocation */
	MLXSW_REG_PTAR_OP_TEST,
};

enum mlxsw_reg_ptar_key_type {
	MLXSW_REG_PTAR_KEY_TYPE_FLEX = 0x50, /* Spetrum */
	MLXSW_REG_PTAR_KEY_TYPE_FLEX2 = 0x51, /* Spectrum-2 */
};

#define MLXSW_REG_PTCE3_ID 0x3027

enum mlxsw_reg_ptce3_op {
	/* Write operation. Used to write a new entry to the table.
	 * All R/W fields are relevant for new entry. Activity bit is set
	 * for new entries. Write with v = 0 will delete the entry. Must
	 * not be used if an entry exists.
	 */
	 MLXSW_REG_PTCE3_OP_WRITE_WRITE = 0,
	 /* Update operation */
	 MLXSW_REG_PTCE3_OP_WRITE_UPDATE = 1,
	 /* Read operation */
	 MLXSW_REG_PTCE3_OP_QUERY_READ = 0,
};

#define MLXSW_REG_PEFA_ID 0x300F
#define MLXSW_REG_IEDR_ID 0x3804

#define MLXSW_REG_RAUHT_ID 0x8014

enum mlxsw_reg_rauht_op {
	/* Read operation */
	MLXSW_REG_RAUHT_OP_QUERY_READ = 0,
	/* Clear on read operation. Used to read entry and clear
	 * activity bit.
	 */
	MLXSW_REG_RAUHT_OP_QUERY_CLEAR_ON_READ = 1,
	/* Add. Used to write a new entry to the table. All R/W fields are
	 * relevant for new entry. Activity bit is set for new entries.
	 */
	MLXSW_REG_RAUHT_OP_WRITE_ADD = 0,
	/* Update action. Used to update an existing route entry and
	 * only update the following fields:
	 * trap_action, trap_id, mac, counter_set_type, counter_index
	 */
	MLXSW_REG_RAUHT_OP_WRITE_UPDATE = 1,
	/* Clear activity. A bit is cleared for the entry. */
	MLXSW_REG_RAUHT_OP_WRITE_CLEAR_ACTIVITY = 2,
	/* Delete entry */
	MLXSW_REG_RAUHT_OP_WRITE_DELETE = 3,
	/* Delete all host entries on a RIF. In this command, dip
	 * field is reserved.
	 */
	MLXSW_REG_RAUHT_OP_WRITE_DELETE_ALL = 4,
};

#define MLXSW_REG_RATR_ID 0x8008

enum mlxsw_reg_ratr_op {
	/* Read */
	MLXSW_REG_RATR_OP_QUERY_READ = 0,
	/* Read and clear activity */
	MLXSW_REG_RATR_OP_QUERY_READ_CLEAR = 2,
	/* Write Adjacency entry */
	MLXSW_REG_RATR_OP_WRITE_WRITE_ENTRY = 1,
	/* Write Adjacency entry only if the activity is cleared.
	 * The write may not succeed if the activity is set. There is not
	 * direct feedback if the write has succeeded or not, however
	 * the get will reveal the actual entry (SW can compare the get
	 * response to the set command).
	 */
	MLXSW_REG_RATR_OP_WRITE_WRITE_ENTRY_ON_ACTIVITY = 3,
};

#define MLXSW_REG_SFD_ID 0x200A

enum mlxsw_reg_sfd_op {
	/* Dump entire FDB a (process according to record_locator) */
	MLXSW_REG_SFD_OP_QUERY_DUMP = 0,
	/* Query records by {MAC, VID/FID} value */
	MLXSW_REG_SFD_OP_QUERY_QUERY = 1,
	/* Query and clear activity. Query records by {MAC, VID/FID} value */
	MLXSW_REG_SFD_OP_QUERY_QUERY_AND_CLEAR_ACTIVITY = 2,
	/* Test. Response indicates if each of the records could be
	 * added to the FDB.
	 */
	MLXSW_REG_SFD_OP_WRITE_TEST = 0,
	/* Add/modify. Aged-out records cannot be added. This command removes
	 * the learning notification of the {MAC, VID/FID}. Response includes
	 * the entries that were added to the FDB.
	 */
	MLXSW_REG_SFD_OP_WRITE_EDIT = 1,
	/* Remove record by {MAC, VID/FID}. This command also removes
	 * the learning notification and aged-out notifications
	 * of the {MAC, VID/FID}. The response provides current (pre-removal)
	 * entries as non-aged-out.
	 */
	MLXSW_REG_SFD_OP_WRITE_REMOVE = 2,
	/* Remove learned notification by {MAC, VID/FID}. The response provides
	 * the removed learning notification.
	 */
	MLXSW_REG_SFD_OP_WRITE_REMOVE_NOTIFICATION = 2,
};

enum mlxsw_reg_sfd_rec_type {
	MLXSW_REG_SFD_REC_TYPE_UNICAST = 0x0,
	MLXSW_REG_SFD_REC_TYPE_UNICAST_LAG = 0x1,
	MLXSW_REG_SFD_REC_TYPE_MULTICAST = 0x2,
	MLXSW_REG_SFD_REC_TYPE_UNICAST_TUNNEL = 0xC,
};

#define MLXSW_REG_SFDF_ID 0x2013

enum mlxsw_reg_sfdf_flush_type {
	/* All SWID dynamic entries are flushed. */
	MLXSW_REG_SFDF_FLUSH_PER_SWID,
	/* All FID dynamic entries are flushed. */
	MLXSW_REG_SFDF_FLUSH_PER_FID,
	/* All dynamic entries pointing to port are flushed. */
	MLXSW_REG_SFDF_FLUSH_PER_PORT,
	/* All FID dynamic entries pointing to port are flushed. */
	MLXSW_REG_SFDF_FLUSH_PER_PORT_AND_FID,
	/* All dynamic entries pointing to LAG are flushed. */
	MLXSW_REG_SFDF_FLUSH_PER_LAG,
	/* All FID dynamic entries pointing to LAG are flushed. */
	MLXSW_REG_SFDF_FLUSH_PER_LAG_AND_FID,
	/* All entries of type "Unicast Tunnel" or "Multicast Tunnel" are
	 * flushed.
	 */
	MLXSW_REG_SFDF_FLUSH_PER_NVE,
	/* All entries of type "Unicast Tunnel" or "Multicast Tunnel" are
	 * flushed, per FID.
	 */
	MLXSW_REG_SFDF_FLUSH_PER_NVE_AND_FID,
};

#define MLXSW_REG_SVFA_ID 0x201C

enum mlxsw_reg_svfa_mt {
	MLXSW_REG_SVFA_MT_VID_TO_FID,
	MLXSW_REG_SVFA_MT_PORT_VID_TO_FID,
	MLXSW_REG_SVFA_MT_VNI_TO_FID,
};

#define MLXSW_REG_RIPS_ID 0x8021
