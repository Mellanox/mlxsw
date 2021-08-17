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

####################### Stop resmon #######################
$RESMON stop
exit $EXIT_STATUS
