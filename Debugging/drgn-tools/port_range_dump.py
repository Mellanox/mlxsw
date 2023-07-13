# port_range_dump   Dump port range registers in JSON format

from drgn.helpers.linux.xarray import xa_for_each
from mlxsw_drgn import *
import json
import sys

mlxsw_sp = MlxswSp.find()
dump = {}

dump_prrs = {}
dump["port_range_registers"] = dump_prrs

for index, entry in xa_for_each(mlxsw_sp.pr_core.prr_xa):
    dump_prr = {}
    dump_prrs[index] = dump_prr

    mlxsw_sp_port_range_reg = drgn.cast("struct mlxsw_sp_port_range_reg *",
                                        entry)
    dump_prr["min_port"] = mlxsw_sp_port_range_reg.range.min.value_()
    dump_prr["max_port"] = mlxsw_sp_port_range_reg.range.max.value_()
    dump_prr["is_source"] = bool(mlxsw_sp_port_range_reg.range.source.value_())
    dump_prr["refcount"] = mlxsw_sp_port_range_reg.refcount.refs.counter.value_()
    dump_prr["index"] = mlxsw_sp_port_range_reg.index.value_()

sys.stdout.write(json.dumps(dump))
