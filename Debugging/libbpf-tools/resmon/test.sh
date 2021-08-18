#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

EXIT_STATUS=0
RESMON="./.output/resmon --sockdir ."

op_tlv_get()
{
	local type_len_status="08040000"
	local reg_id=$1
	local r_method_emadclass="8201"
	local tid="2d68bbc20004cbd3"

	echo "$type_len_status$reg_id$r_method_emadclass$tid"
}

resmon_stats_no_change_test()
{
	local payload=$1; shift

	$RESMON stats &> /tmp/before
	$RESMON emad string "$payload" 2>/dev/null
	$RESMON stats &> /tmp/after

	diff /tmp/before /tmp/after
	if [[ $? -ne 0 ]]; then
		EXIT_STATUS=1
	fi

	rm /tmp/before /tmp/after
}

resmon_stats_test()
{
	local payload=$1; shift
	local gauge_name=$1; shift
	local num_entries=$1; shift
	local expected_val
	local val_before
	local val_after

	val_before=$((echo -n '{ "jsonrpc": "2.0", "id": 1, "method": "stats" }'; \
		sleep 0.2) | nc -U --udp resmon.ctl | \
		jq ".result.gauges[] | select(.name == \"$gauge_name\")".value)

	$RESMON emad string "$payload"

	val_after=$((echo -n '{ "jsonrpc": "2.0", "id": 1, "method": "stats" }'; \
		sleep 0.2) | nc -U --udp resmon.ctl | \
		jq ".result.gauges[] | select(.name == \"$gauge_name\")".value)

	expected_val=$((val_before + $num_entries))

	if [[ $expected_val -ne $val_after ]]; then
		echo "$gauge_name is $val_after, but should be $expected_val"
		EXIT_STATUS=1
	fi
}

####################### Common TLVs #######################

string_tlv="10210000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000\
0000000000000000"

end_tlv="00010000"

####################### Start resmon #######################

$RESMON start mode mock&> /dev/null &
sleep 1

################## RALUE - add IPv4 route ##################
reg_id=8013

ralue_type_len="180f0000"
a_op_protocol="00010000"

ralue_payload="00000000\
00000020\
00000000\
00000000\
00000000\
c6010203\
80200002\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000"

reg_tlv=$ralue_type_len$a_op_protocol$ralue_payload

resmon_stats_test $(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv LPM_IPV4 1

################ RALUE - delete IPv4 route ################
reg_id=8013

a_op_protocol="00310000"
reg_tlv=$ralue_type_len$a_op_protocol$ralue_payload

resmon_stats_test $(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv LPM_IPV4 -1

################## RALUE - add IPv6 route ##################
reg_id=8013

a_op_protocol="01010000"
ralue_payload="00010000\
00000040\
20010db8\
00010000\
00000000\
00000000\
80400001\
00000000\
00000001\
00000000\
00000000\
00000000\
00000000"

reg_tlv=$ralue_type_len$a_op_protocol$ralue_payload

resmon_stats_test $(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv LPM_IPV6 1

################ RALUE - delete IPv6 route ################
reg_id=8013

a_op_protocol="01310000"
reg_tlv=$ralue_type_len$a_op_protocol$ralue_payload

resmon_stats_test $(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv LPM_IPV6 -1

############### PTAR - tcam region allocate ###############
reg_id=3006

reg_tlv="180d0000\
00020051\
00000010\
00000002\
00000000\
00001002\
14044101\
02030506\
11124400\
3a139010\
11121415\
38399200\
00000000"

resmon_stats_no_change_test $(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv

################## PTCE-3 - insert entry ##################
reg_id=3027

ptce_payload="0000000\
0007fffe\
00000000\
00000000\
00001002\
14044101\
02030506\
11124400\
00000000\
00000000\
00000000\
00000000\
c6336401\
00000000\
00000008\
00000000\
00000000\
00000000\
00000000\
00d43100\
00000000\
00110000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
000000000\
00003ea00"

ptce_reg_tlv_get()
{
	local v=$1; shift

	local type_len="183d0000"
	local region_id_dup=$(printf '%*s' 150 | tr ' ' "0")

	echo $type_len$v$ptce_payload$region_id_dup
}

resmon_stats_test \
	$(op_tlv_get $reg_id)$string_tlv$(ptce_reg_tlv_get 8)$end_tlv ATCAM 2

################# PTAR - tcam region free #################
reg_id=3006

reg_tlv="180d0000\
00020051\
00000010\
00000002\
00000000\
00001002\
14044101\
02030506\
11124400\
3a139010\
11121415\
38399200\
00000000"

resmon_stats_no_change_test $(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv

################### PTCE-3 - remove entry ##################
reg_id=3027

resmon_stats_test \
	$(op_tlv_get $reg_id)$string_tlv$(ptce_reg_tlv_get 0)$end_tlv ATCAM -2

######## PEFA - accesse to a flexible action entry ########
reg_id=300f

type_len="182d000000"
index="0003ea"
pefa_payload="01000000\
08000000\
00000000\
03000004\
00000000\
00000000\
00000000\
00000000\
00000000\
03000000\
02000003\
000001c3\
00000000\
00000000\
00000000\
00000000\
00000000"

action2_to_action4=$(printf '%*s' 191 | tr ' ' "0")
type_next_goto_record="01000000024000000"

reg_tlv=$type_len$index$pefa_payload$action2_to_action4$type_next_goto_record

resmon_stats_test \
	$(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv ACTSET 1

####### IEDR - delete the entry from the entry table #######

test_iedr_reg_tlv()
{
	local type=$1; shift
	local index=$1; shift
	local gauge_name=$1; shift
	local num_entries=$1; shift


	local reg_id=3804
	local prefix="1885000000000001000000000000000000000000"
	local size="00000100"
	local empty_records=$(printf '%*s' 1008 | tr ' ' "0")

	reg_tlv=$prefix$type$size$index$empty_records

	resmon_stats_test \
		$(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv $gauge_name $num_entries
}

test_iedr_reg_tlv "23" "0003ea" ACTSET -1

############## RAUHT - add IPv4 host table ################
reg_id=8014

reg_tlv="181e0000\
00010002\
00000000\
00000000\
00000000"

ipv4_dip="$(printf '%*s' 24 | tr ' ' "0")c0243a00"
empty_fields=$(printf '%*s' 156 | tr ' ' "0")
mac="001122334455"

reg_tlv=$reg_tlv$ipv4_dip$empty_fields$mac

resmon_stats_test \
	$(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv HOSTTAB_IPV4 1

############## RAUHT - delete IPv4 host table ##############
reg_id=8014

reg_tlv="181e0000\
00310002\
00000000\
00000000\
00000000"

reg_tlv=$reg_tlv$ipv4_dip$empty_fields$mac

resmon_stats_test \
	$(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv HOSTTAB_IPV4 -1

############### RAUHT - add IPv6 host table ################
reg_id=8014

reg_tlv="181e0000\
01010002\
00000000\
00000000\
00000000"

ipv6_dip="20010db8000900000000000000000005"

reg_tlv=$reg_tlv$ipv6_dip$empty_fields$mac

resmon_stats_test \
	$(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv HOSTTAB_IPV6 2

############## RAUHT - delete IPv6 host table ##############
reg_id=8014

reg_tlv="181e0000\
01310002\
00000000\
00000000\
00000000"

reg_tlv=$reg_tlv$ipv6_dip$empty_fields$mac

resmon_stats_test \
	$(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv HOSTTAB_IPV6 -2

####################### Stop resmon #######################
$RESMON stop

############## Start resmon - filter resources ############

$RESMON start mode mock include resources lpm_ipv4 &> /dev/null &
sleep 1

################## RALUE - add IPv6 route ##################
reg_id=8013

a_op_protocol="01010000"
ralue_payload="00010000\
00000040\
20010db8\
00010000\
00000000\
00000000\
80400001\
00000000\
00000001\
00000000\
00000000\
00000000\
00000000"

reg_tlv=$ralue_type_len$a_op_protocol$ralue_payload

resmon_stats_no_change_test $(op_tlv_get $reg_id)$string_tlv$reg_tlv$end_tlv

###################### Stop resmon #######################
$RESMON stop

exit $EXIT_STATUS
