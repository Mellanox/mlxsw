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

    def ports_mapping(self):
        ports_mapping = {}
        for mlxsw_sp_port in self.ports():
            if mlxsw_sp_port.dev.value_() == 0:
                continue

            local_port = mlxsw_sp_port.local_port.value_()
            ports_mapping[local_port] = mlxsw_sp_port.name()

        router_port = self._mlxsw_sp.core.max_ports.value_() + 1
        ports_mapping[router_port] = "router_port"

        return ports_mapping

    @staticmethod
    def find():
        devlinks = prog['devlinks'].address_of_()
        mlxsw_devlink_ops = prog['mlxsw_devlink_ops'].address_of_()
        for _, entry in helpers.xarray.xa_for_each(devlinks):
            devlink = drgn.reinterpret(prog.type("struct devlink *"), entry)
            if devlink.ops == mlxsw_devlink_ops:
                mlxsw_core = drgn.reinterpret(prog.type("struct mlxsw_core"),
                                              devlink.priv)
                mlxsw_sp = drgn.reinterpret(prog.type("struct mlxsw_sp"),
                                            mlxsw_core.driver_priv)
                return MlxswSp(mlxsw_sp)
        raise RuntimeError("mlxsw devlink instance not found")

    def netns(self):
        mlxsw_core = self._mlxsw_sp.core
        devlink = drgn.container_of(mlxsw_core, "struct devlink", "priv")

        return devlink._net.net

def enum_name(in_enum):
    enum_n, = list(enum.name
                   for enum in in_enum.type_.enumerators
                   if enum.value == in_enum.value_())

    return enum_n.split("_")[-1]
