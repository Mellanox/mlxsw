local emad = Proto("emad", "Mellanox EMAD configuration packets")
local EMAD_ETHER_TYPE = 0x8932

local EMAD_TLV_TYPE = {
	[0x0] = "End",
	[0x1] = "Operation",
	[0x2] = "String",
	[0x3] = "Reg"
}

----------------------EMAD_header_fields----------------------
pf_eth_hdr_mlx_proto = ProtoField.uint8("eth_hdr.mlx_proto", "Mellanox protocol", base.HEX)
pf_eth_hdr_ver = ProtoField.uint8("eth_hdr.ver", "Protocol version", base.HEX)

----------------------operation_tlv_fields----------------------
local OP_TLV_STATUS = {
	[0x0] = "Operation performed",
	[0x1] = "Device is busy",
	[0x2] = "Version not supported",
	[0x3] = "Unknown TLV",
	[0x4] = "Register not supported",
	[0x5] = "Class not supported",
	[0x6] = "Method not supported",
	[0x7] = "Bad parameter",
	[0x8] = "Resource not available",
	[0x9] = "Acknowledged",
	[0xA] = "Retry",
	[0x70] = "Internal error"
}

local OP_TLV_REG_ID = {
	[0x0] = "None",
	[0x2000] = "SGCR",
	[0x2002] = "SPAD",
	[0x2007] = "SMID",
	[0x2008] = "SSPR",
	[0x2009] = "SFDAT",
	[0x200A] = "SFD",
	[0x200B] = "SFN",
	[0x200D] = "SPMS",
	[0x200E] = "SPVID",
	[0x200F] = "SPVM",
	[0x2010] = "SPAFT",
	[0x2011] = "SFGC",
	[0x2012] = "SFTR",
	[0x2013] = "SFDF",
	[0x2014] = "SLDR",
	[0x2015] = "SLCR",
	[0x2016] = "SLCOR",
	[0x2018] = "SPMLR",
	[0x201C] = "SVFA",
	[0x201D] = "SPVTR",
	[0x201E] = "SVPE",
	[0x201F] = "SFMR",
	[0x2020] = "SPVMLR",
	[0x202A] = "SPEVET",
	[0x2082] = "CWTP",
	[0x2803] = "CWTPM",
	[0x3001] = "PGCR",
	[0x3002] = "PPBT",
	[0x3004] = "PACL",
	[0x3005] = "PAGT",
	[0x3006] = "PTAR",
	[0x300C] = "PPBS",
	[0x300D] = "PRCR",
	[0x300F] = "PEFA",
	[0x3014] = "PEMRBT",
	[0x3017] = "PTCE2",
	[0x3021] = "PERPT",
	[0x3022] = "PEABFE",
	[0x3026] = "PERAR",
	[0x3027] = "PTCE3",
	[0x302A] = "PERCR",
	[0x302B] = "PERERP",
	[0x3804] = "IEDR",
	[0x4002] = "QPTS",
	[0x4004] = "QPCR",
	[0x400A] = "QTCT",
	[0x400D] = "QEEC",
	[0x400F] = "QRWE",
	[0x4011] = "QPDSM",
	[0x4007] = "QPDP",
	[0x4013] = "QPDPM",
	[0x401A] = "QTCTM",
	[0x401B] = "QPSC",
	[0x5002] = "PMLP",
	[0x5003] = "PMTU",
	[0x5004] = "PTYS",
	[0x5005] = "PPAD",
	[0x5006] = "PAOS",
	[0x5007] = "PFCC",
	[0x5008] = "PPCNT",
	[0x500A] = "PLIB",
	[0x500B] = "PPTB",
	[0x500C] = "PBMC",
	[0x500D] = "PSPA",
	[0x5018] = "PPLR",
	[0x5067] = "PMTM",
	[0x7002] = "HTGT",
	[0x7003] = "HPKT",
	[0x8001] = "RGCR",
	[0x8002] = "RITR",
	[0x8004] = "RTAR",
	[0x8008] = "RATR",
	[0x8020] = "RTDP",
	[0x8009] = "RDPM",
	[0x800B] = "RICNT",
	[0x800F] = "RRCR",
	[0x8010] = "RALTA",
	[0x8011] = "RALST",
	[0x8012] = "RALTB",
	[0x8013] = "RALUE",
	[0x8014] = "RAUHT",
	[0x8015] = "RALEU",
	[0x8018] = "RAUHTD",
	[0x8023] = "RIGR2",
	[0x8025] = "RECR2",
	[0x8027] = "RMFT2",
	[0x9001] = "MFCR",
	[0x9002] = "MFSC",
	[0x9003] = "MFSM",
	[0x9004] = "MFSL",
	[0x9007] = "FORE",
	[0x9009] = "MTCAP",
	[0x900A] = "MTMP",
	[0x900F] = "MTBR",
	[0x9014] = "MCIA",
	[0x901A] = "MPAT",
	[0x901B] = "MPAR",
	[0x9020] = "MGIR",
	[0x9023] = "MRSR",
	[0x902B] = "MLCR",
	[0x9053] = "MTPPS",
	[0x9055] = "MTUTC",
	[0x9080] = "MPSC",
	[0x9061] = "MCQI",
	[0x9062] = "MCC",
	[0x9063] = "MCDA",
	[0x901C] = "MGPC",
	[0x9083] = "MPRS",
	[0x9086] = "MOGCR",
	[0x9090] = "MTPPPC",
	[0x9091] = "MTPPTR",
	[0x9092] = "MTPTPT",
	[0x9100] = "MGPIR",
	[0xA001] = "TNGCR",
	[0xA003] = "TNUMT",
	[0xA010] = "TNQCR",
	[0xA011] = "TNQDR",
	[0xA012] = "TNEEM",
	[0xA013] = "TNDEM",
	[0xA020] = "TNPC",
	[0xA801] = "TIGCR",
	[0xA812] = "TIEEM",
	[0xA813] = "TIDEM",
	[0xB001] = "SBPR",
	[0xB002] = "SBCM",
	[0xB003] = "SBPM",
	[0xB005] = "SBSR",
	[0xB006] = "SBIB"
}

local OP_TLV_R = {
	[0x0] = "Request",
	[0x1] = "Response"
}

local OP_TLV_METHOD = {
	[0x1] = "Query",
	[0x2] = "Write",
	[0x5] = "Event"
}

local OP_TLV_CLASS = {
	[0x0] = "Reserved",
	[0x1] = "Reg access"
}

pf_op_tlv_type = ProtoField.uint8("op_tlv.type", "Type", base.HEX, EMAD_TLV_TYPE)
pf_op_tlv_len = ProtoField.uint16("op_tlv.len", "Len", base.HEX)
pf_op_tlv_status = ProtoField.uint8("op_tlv.status", "Status", base.HEX, OP_TLV_STATUS)
pf_op_tlv_register_id = ProtoField.uint16("op_tlv.register_id", "Register ID", base.HEX, OP_TLV_REG_ID)
pf_op_tlv_r = ProtoField.uint8("op_tlv.r", "Request/Response", base.HEX, OP_TLV_R)
pf_op_tlv_method = ProtoField.uint8("op_tlv.method", "Method", base.HEX, OP_TLV_METHOD)
pf_op_tlv_class = ProtoField.uint8("op_tlv.class", "Class", base.HEX, OP_TLV_CLASS)
pf_op_tlv_tid = ProtoField.uint64("op_tlv.tid", "Transaction ID", base.HEX)

----------------------string_tlv_fields----------------------
pf_string_tlv_type = ProtoField.uint8("string_tlv.type", "Type", base.HEX, EMAD_TLV_TYPE)
pf_string_tlv_len = ProtoField.uint16("string_tlv.len", "Len", base.HEX)
pf_string_tlv_string = ProtoField.string("string_tlv.string", "String", base.ASCII)

----------------------reg_tlv_fields----------------------
pf_reg_tlv_type = ProtoField.uint8("reg_tlv.type", "Type", base.HEX, EMAD_TLV_TYPE)
pf_reg_tlv_len = ProtoField.uint16("reg_tlv.len", "Len", base.HEX)
pf_reg_tlv_switch_register = ProtoField.bytes("reg_tlv.switch_register", "Register payload")

----------------------end_tlv_fields----------------------
pf_end_tlv_type = ProtoField.uint8("end_tlv.type", "Type", base.HEX, EMAD_TLV_TYPE)
pf_end_tlv_len = ProtoField.uint16("end_tlv.len", "Len", base.HEX)

function emad_header(tvbuf, tree)
	tree:add(pf_eth_hdr_mlx_proto, tvbuf:range(0, 1))
	tree:add(pf_eth_hdr_ver, tvbuf:range(1, 1), tvbuf(1,1):bitfield(4, 4))
end

emad.fields = {
	pf_eth_hdr_mlx_proto,
	pf_eth_hdr_ver,
	pf_op_tlv_type,
	pf_op_tlv_len,
	pf_op_tlv_status,
	pf_op_tlv_register_id,
	pf_op_tlv_r,
	pf_op_tlv_method,
	pf_op_tlv_class,
	pf_op_tlv_tid,
	pf_string_tlv_type,
	pf_string_tlv_len,
	pf_string_tlv_string,
	pf_reg_tlv_type,
	pf_reg_tlv_len,
	pf_reg_tlv_switch_register,
	pf_end_tlv_type,
	pf_end_tlv_len
}

function emad_tlv_len_add(tvbuf, tree, proto_field)
	-- The len is represnted by number of dwords, have to multiply by 4
	local len_dwords = tvbuf(0, 2):bitfield(5, 11)
	local len_str = tostring(len_dwords * 4) .. 'B'

	tree:add(proto_field, tvbuf(0, 2), tvbuf(0, 2):bitfield(5, 11)):
		append_text(" (" .. len_str .. ")")
end

function emad_tlv_len_get(tvbuf)
	-- The len is represnted by number of dwords, have to multiply by 4
	local len_dwords = tvbuf(0, 2):bitfield(5, 11)
	return len_dwords * 4
end

function emad_op_tlv(tvbuf, tree)
	tree:add(pf_op_tlv_type, tvbuf(0, 1), tvbuf(0, 1):bitfield(0, 5))
	emad_tlv_len_add(tvbuf, tree, pf_op_tlv_len)
	tree:add(pf_op_tlv_status, tvbuf(2, 1), tvbuf(2, 1):bitfield(1, 7))
	tree:add(pf_op_tlv_register_id, tvbuf(4, 2))
	tree:add(pf_op_tlv_r, tvbuf(6, 1), tvbuf(6, 1):bitfield(0, 1))
	tree:add(pf_op_tlv_method, tvbuf(6, 1), tvbuf(6, 1):bitfield(1, 7))
	tree:add(pf_op_tlv_class, tvbuf(7, 1), tvbuf(7, 1):bitfield(4, 4))
	tree:add(pf_op_tlv_tid, tvbuf(8, 8))
end

function emad_string_tlv(tvbuf, tree)
	tree:add(pf_string_tlv_type, tvbuf(0, 1), tvbuf(0, 1):bitfield(0, 5))
	emad_tlv_len_add(tvbuf, tree, pf_string_tlv_len)
	tree:add(pf_string_tlv_string, tvbuf(4, 126))
end

function emad_reg_tlv(tvbuf, tree)
	tree:add(pf_reg_tlv_type, tvbuf(0, 1), tvbuf(0, 1):bitfield(0, 5))
	emad_tlv_len_add(tvbuf, tree, pf_reg_tlv_len)
	tree:add(pf_reg_tlv_switch_register, tvbuf(2))
end

function emad_end_tlv(tvbuf, tree)
	tree:add(pf_end_tlv_type, tvbuf(0, 1), tvbuf(0, 1):bitfield(0, 5))
	emad_tlv_len_add(tvbuf, tree, pf_end_tlv_len)
end

function emad.dissector(tvbuf, pktinfo, root)
	length = tvbuf:len()
	if length == 0 then
		return
	end

	pktinfo.cols.protocol:set("EMAD")
	local current_index = 0

	-- EMAD_header --
	local emad_header_len = 2
	local emad_header_subtree = root:add(emad, tvbuf:range(current_index, emad_header_len), "EMAD header")
	emad_header(tvbuf(current_index, emad_header_len), emad_header_subtree)
	current_index = current_index + emad_header_len

	local subtree = root:add(emad, tvbuf:range(current_index), "EMAD Protocol Data")

	-- operation_tlv --
	local op_tlv_len = emad_tlv_len_get(tvbuf:range(current_index))
	local op_tlv_subtree = subtree:add(emad, tvbuf:range(current_index, op_tlv_len), "Operation TLV")
	emad_op_tlv(tvbuf(current_index, op_tlv_len), op_tlv_subtree)
	current_index = current_index + op_tlv_len

	-- string_tlv --
	local string_tlv_len = emad_tlv_len_get(tvbuf:range(current_index))
	local string_tlv_subtree = subtree:add(emad, tvbuf:range(current_index, string_tlv_len), "String TLV")
	emad_string_tlv(tvbuf(current_index, string_tlv_len), string_tlv_subtree)
	current_index = current_index + string_tlv_len

	-- reg_tlv --
	local reg_tlv_len = emad_tlv_len_get(tvbuf:range(current_index))
	local reg_tlv_subtree = subtree:add(emad, tvbuf:range(current_index, reg_tlv_len), "Reg TLV")
	emad_reg_tlv(tvbuf(current_index, reg_tlv_len), reg_tlv_subtree)
	current_index = current_index + reg_tlv_len

	-- end_tlv --
	local end_tlv_len = emad_tlv_len_get(tvbuf:range(current_index))
	local end_tlv_subtree = subtree:add(emad, tvbuf:range(current_index, end_tlv_len), "End TLV")
	emad_end_tlv(tvbuf(current_index, end_tlv_len), end_tlv_subtree)
end

--- Invoke our dissector only for packets with specific EtherType
DissectorTable.get("ethertype"):add(EMAD_ETHER_TYPE, emad)
