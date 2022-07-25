# pgt table dump - Dump PGT table in JSON format

from drgn.helpers.linux.idr import idr_for_each
from mlxsw_drgn import *
import json
import sys

mlxsw_sp = MlxswSp.find()
ports_mapping = mlxsw_sp.ports_mapping()

dump = {}
dump["end_index"] = mlxsw_sp.pgt.end_index.value_()

smpe_index_valid = mlxsw_sp.pgt.smpe_index_valid.value_()
dump["smpe_index_valid"] = smpe_index_valid

dump_pgt_entries = {}
dump["pgt_entries"] = dump_pgt_entries

for index, entry in idr_for_each(mlxsw_sp.pgt.pgt_idr):
    dump_pgt_entry = {}
    dump_pgt_entries[index] = dump_pgt_entry

    mlxsw_sp_pgt_entry = drgn.cast("struct mlxsw_sp_pgt_entry *", entry)
    dump_pgt_entry["mid_index"] = mlxsw_sp_pgt_entry.index.value_()

    if smpe_index_valid:
        dump_pgt_entry["smpe_index"] = mlxsw_sp_pgt_entry.smpe_index.value_()

    dump_pgt_entry_ports = {}
    dump_pgt_entry["ports"] = dump_pgt_entry_ports

    for entry_port in \
        helpers.list_for_each_entry("struct mlxsw_sp_pgt_entry_port",
                                    mlxsw_sp_pgt_entry.ports_list.address_of_(),
                                    "list"):
        swp = ports_mapping[entry_port.local_port.value_()]

        dump_entry_port = {}
        dump_pgt_entry_ports[swp] = dump_entry_port

        dump_entry_port["local_port"] = entry_port.local_port.value_()

sys.stdout.write(json.dumps(dump))
