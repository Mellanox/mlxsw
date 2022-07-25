# mdb table dump - Dump MDB table in JSON format

from mlxsw_drgn import *
import json
import sys

mlxsw_sp = MlxswSp.find()
ports_mapping = mlxsw_sp.ports_mapping()

dump = {}

def port_list_dump(mdb_entry, dump_ports_list):
    ports_list = mdb_entry.ports_list
    for entry_port in helpers.list_for_each_entry("struct mlxsw_sp_mdb_entry_port",
                                                  ports_list.address_of_(),
                                                  "list"):
        dump_entry_port = {}
        swp = ports_mapping[entry_port.local_port.value_()]

        dump_ports_list[swp] = dump_entry_port

        dump_entry_port["local_port"] = entry_port.local_port.value_()
        dump_entry_port["refcount"] = entry_port.refcount.refs.counter.value_()
        dump_entry_port["mrouter"] = entry_port.mrouter.value_()

def mac_addr_get(mac_array):
    return ":".join("%02x" % x for x in mac_array)

bridges_list = mlxsw_sp.bridge.bridges_list
for bridge_dev in helpers.list_for_each_entry("struct mlxsw_sp_bridge_device",
                                              bridges_list.address_of_(),
                                              "list"):
    br_dev_name = bridge_dev.dev.name.string_().decode("utf-8")

    dump_bridge_dev = {}
    dump[br_dev_name] = dump_bridge_dev

    mdb_list = bridge_dev.mdb_list
    for mdb_entry in helpers.list_for_each_entry("struct mlxsw_sp_mdb_entry",
                                                 mdb_list.address_of_(),
                                                 "list"):
        dump_mdb_entry = {}
        dump_bridge_dev[mdb_entry.mid.value_()] = dump_mdb_entry

        dump_mdb_entry["mac_address"] = mac_addr_get(mdb_entry.key.addr.value_())
        dump_mdb_entry["fid_index"] = mdb_entry.key.fid.value_()
        dump_mdb_entry["mid_index"] = mdb_entry.mid.value_()

        dump_ports_list = {}
        dump_mdb_entry["ports_list"] = dump_ports_list
        port_list_dump(mdb_entry, dump_ports_list)

sys.stdout.write(json.dumps(dump))
