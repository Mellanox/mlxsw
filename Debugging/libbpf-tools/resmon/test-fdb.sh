#! /bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

sfd_reg_tlv_get()
{
	local op=$1; shift
	local num_rec=$1; shift

	local type_len="19050000"
	local swid_rec_type="00000000"
	local record_locator="0000000"
	local resv1="000000"
	local resv2="00000000"

	echo $type_len$swid_rec_type$op$record_locator$resv1$num_rec$resv2
}

sfd_record_get()
{
	local type=$1; shift
	local mac_31_0=$1; shift
	local mac_47_32=$1; shift
	local fid_vid=$1; shift
	# Depends on record type:
	# For type=0x0: param is system_port
	# For type=0x1: param is lag_id
	# For type=0x2: param is mid
	# For type=0xc: param is tunnel_port
	local param=$1; shift

	local swid="00"
	local policy_a="0"
	local resv1="0000"
	local resv2="0000"
	local resv3=$(printf '%*s' 32 | tr ' ' "0")

	echo $swid$type$policy_a$mac_47_32$mac_31_0$resv1$fid_vid$resv2$param$resv3
}

sfd_reg_payload_get()
{
	local op=$1; shift
	local record_type=${1:-"0"}; shift
	local fid=${1:-"1000"}; shift
	local mac_47_32=${1:-"aabb"}; shift

	local num_rec="01"
	local reg_tlv_part_1=$(sfd_reg_tlv_get $op $num_rec)

	local mac_31_0="ccddeeff"
	local system_port="0069"

	local sfd_record=$(sfd_record_get $record_type $mac_31_0 $mac_47_32 $fid $system_port)

	local rec_len=32
	local num_empty_rec=63
	local empty_records_len=$(( $rec_len * $num_empty_rec ))
	local empty_records=$(printf '%*s' $empty_records_len | tr ' ' "0")

	echo $reg_tlv_part_1$sfd_record$empty_records
}

sfdf_reg_payload_get()
{
	local flush_type=$1; shift
	local param=$1; shift

	local type_len="18060000"
	local resv1="00000000"
	local resv2="1000000"
	local resv_param="000000000000"
	local resv3="00000000"

	echo $type_len$resv1$flush_type$resv2$resv_param$param$resv3
}
