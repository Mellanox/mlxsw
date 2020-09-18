# This module collects helpers related to working with the mlxsw Spectrum
# driver. But since it's a module, the drgn `prog' variable is not available. So
# we need to construct it anew. Then once we have it, we can export it to the
# tool, and use drgn as just a library, and run the tool through python.

import sys
import drgn
import drgn.helpers.linux as helpers

prog = drgn.Program()
prog.set_kernel()

try:
    prog.load_debug_info(None, default=True, main=True)
except drgn.MissingDebugInfoError as e:
    print(str(e), file=sys.stderr)

class MlxswSpPort:
    def __init__(self, _mlxsw_sp_port):
        self._mlxsw_sp_port = _mlxsw_sp_port
    def __getattr__(self, key):
        return getattr(self._mlxsw_sp_port, key)

    def name(self):
        dev = self._mlxsw_sp_port.dev
        if dev.value_() == 0:
            raise RuntimeError("No netdev associated with the port")
        return dev.name.string_().decode("utf-8")

class MlxswSp:
    def __init__(self, _mlxsw_sp):
        self._mlxsw_sp = _mlxsw_sp
    def __getattr__(self, key):
        return getattr(self._mlxsw_sp, key)

    def ports(self):
        mlxsw_core = self._mlxsw_sp.core
        max_ports = mlxsw_core.max_ports.value_() - 1
        for i in range(0, max_ports):
            if self._mlxsw_sp.ports[i].value_() == 0:
                continue
            yield MlxswSpPort(self._mlxsw_sp.ports[i])

    @staticmethod
    def find():
        devlink_list = prog['devlink_list'].address_of_()
        mlxsw_devlink_ops = prog['mlxsw_devlink_ops'].address_of_()
        for devlink in helpers.list_for_each_entry('struct devlink',
                                                   devlink_list, 'list'):
            if devlink.ops == mlxsw_devlink_ops:
                mlxsw_core = drgn.reinterpret(prog.type("struct mlxsw_core"),
                                            devlink.priv)
                mlxsw_sp = drgn.reinterpret(prog.type("struct mlxsw_sp"),
                                            mlxsw_core.driver_priv)
                return MlxswSp(mlxsw_sp)
        raise RuntimeError("mlxsw devlink instance not found")
