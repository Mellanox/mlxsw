# res_dump   Dump device resources in JSON format

from socket import ntohl
from mlxsw_drgn import *
import json
import sys

mlxsw_sp = MlxswSp.find()
dump = {}

for res_idx, res_id in enumerate(prog['mlxsw_res_ids']):
    res_enum = prog.type('enum mlxsw_res_id').enumerators[res_idx]
    res_name = res_enum.name[len("MLXSW_RES_ID_"):]

    res = {}
    res["id"] = hex(res_id)
    res["valid"] = mlxsw_sp.core.res.valid[res_idx].value_()
    res["value"] = mlxsw_sp.core.res.values[res_idx].value_()
    dump[res_name] = res

sys.stdout.write(json.dumps(dump))
