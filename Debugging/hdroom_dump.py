# hdroom_dump   Dump mlxsw port headroom configuration in JSON format

from mlxsw_drgn import *
import json
import sys

mlxsw_sp = MlxswSp.find()
dump = {}
dump_ports = {}
dump["ports"] = dump_ports
dump["max_headroom_cells"] = mlxsw_sp.sb.max_headroom_cells.value_();
dump["cell_size"] = mlxsw_sp.sb.cell_size.value_();
for mlxsw_sp_port in mlxsw_sp.ports():
    hdroom = mlxsw_sp_port.hdroom
    if hdroom.value_() == 0:
        continue

    dump_port = {}
    dump_ports[mlxsw_sp_port.name()] = dump_port

    dump_port["max_mtu"] = mlxsw_sp_port.max_mtu.value_()
    dump_port["max_speed"] = mlxsw_sp_port.max_speed.value_()

    mode = hdroom.mode
    mode_t = mode.type_
    mode_n, = list(enum.name
                   for enum in mode_t.enumerators
                   if enum.value == mode.value_())
    mode_n = mode_n.split("_", 4)[-1]

    dump_port["mode"] = mode_n
    dump_port["mtu"] = hdroom.mtu.value_()
    dump_port["delay_bytes"] = hdroom.delay_bytes.value_()

    dump_prios = {}
    dump_port["prios"] = dump_prios
    for mlxsw_sp_hdroom_prio in hdroom.prios.prio:
        dump_prio = {
            "buf_idx": mlxsw_sp_hdroom_prio.buf_idx.value_(),
            "ets_buf_idx": mlxsw_sp_hdroom_prio.ets_buf_idx.value_(),
            "set_buf_idx": mlxsw_sp_hdroom_prio.set_buf_idx.value_(),
            "lossy": mlxsw_sp_hdroom_prio.lossy.value_(),
        }
        dump_prios[len(dump_prios)] = dump_prio

    dump_bufs = {}
    dump_port["bufs"] = dump_bufs
    for mlxsw_sp_hdroom_buf in hdroom.bufs.buf:
        dump_buf = {
            "thres_cells": mlxsw_sp_hdroom_buf.thres_cells.value_(),
            "size_cells": mlxsw_sp_hdroom_buf.size_cells.value_(),
            "lossy": mlxsw_sp_hdroom_buf.lossy.value_(),
        }
        dump_bufs[len(dump_bufs)] = dump_buf

    dump_int_buf = {
        "enable": hdroom.int_buf.enable.value_(),
        "size_cells": hdroom.int_buf.size_cells.value_(),
        "reserve_cells": hdroom.int_buf.reserve_cells.value_(),
    }
    dump_port["int_buf"] = dump_int_buf

sys.stdout.write(json.dumps(dump))
