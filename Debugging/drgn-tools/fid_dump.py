# fid_dump   Dump FID configuration in JSON format

from socket import ntohl
from mlxsw_drgn import *
import json
import sys

mlxsw_sp = MlxswSp.find()
dump = {}

def mid_indexes_dump(fid, dump_fid):
    dump_mid_indexes = {}
    dump_fid["flood_mid_indexes"] = dump_mid_indexes

    fid_family = fid.fid_family
    flood_tables = fid_family.flood_tables

    num_fids_in_family = fid_family.end_index.value_() - \
                         fid_family.start_index.value_() + 1

    for i in range(fid_family.nr_flood_tables.value_()):
        flood_table = flood_tables[i]
        packet_type_n = enum_name(flood_table.packet_type)

        # Same to the calculation in mlxsw_sp_fid_flood_table_mid().
        mid_index = fid_family.pgt_base.value_() + \
                    num_fids_in_family * flood_table.table_index.value_() + \
                    fid.fid_offset.value_()
        dump_mid_indexes[packet_type_n] = mid_index

dump_ports = {}
dump["ports"] = dump_ports

for mlxsw_sp_port in mlxsw_sp.ports():
    if mlxsw_sp_port.dev.value_() == 0:
        continue

    dump_port = {}
    dump_ports[mlxsw_sp_port.name()] = dump_port

    local_port = mlxsw_sp_port.local_port.value_()
    virtual = mlxsw_sp.fid_core.port_fid_mappings[local_port] != 0

    dump_port["local_port"] = local_port
    dump_port["virtual"] = virtual

dump_fid_families = {}
dump["fid_families"] = dump_fid_families

for family in mlxsw_sp.fid_core.fid_family_arr:
    dump_fid_family = {}
    family_type_n = enum_name(family.type)
    dump_fid_families[family_type_n] = dump_fid_family

    dump_fid_family["start_index"] = family.start_index.value_()
    dump_fid_family["end_index"] = family.end_index.value_()
    dump_fid_family["rif_type"] = enum_name(family.rif_type)

    dump_fids = {}
    dump_fid_family["fids"] = dump_fids

    for fid in helpers.list_for_each_entry("struct mlxsw_sp_fid",
                                           family.fids_list.address_of_(),
                                           "list"):
        dump_fid = {}
        dump_fids[fid.fid_index.value_()] = dump_fid
        dump_fid["fid_offset"] = fid.fid_offset.value_()

        if family_type_n == "8021Q":
            fid_8021q = drgn.container_of(fid, "struct mlxsw_sp_fid_8021q",
                                          "common")
            dump_fid["vid"] = fid_8021q.vid.value_()

        if family_type_n == "8021D":
            fid_8021d = drgn.container_of(fid, "struct mlxsw_sp_fid_8021d",
                                          "common")
            br_ifindex = fid_8021d.br_ifindex.value_()
            br_dev = helpers.net.netdev_get_by_index(mlxsw_sp.netns(),
                                                     br_ifindex)

            dump_fid["br_ifindex"] = br_ifindex
            dump_fid["br_ifname"] = br_dev.name.string_().decode("utf-8")

        dump_fid["ref_count"] = fid.ref_count.refs.counter.value_()

        if fid.rif.value_():
            rif_dump = {}
            dump_fid["rif"] = rif_dump

            rif_dump["index"] = fid.rif.rif_index.value_()
            rif_dump["ifindex"] = fid.rif.dev.ifindex.value_()
            rif_dump["ifname"] = fid.rif.dev.name.string_().decode("utf-8")

        if fid.vni_valid.value_():
            nve_ifindex = fid.nve_ifindex.value_()
            nve_dev = helpers.net.netdev_get_by_index(mlxsw_sp.netns(),
                                                      nve_ifindex)

            dump_fid["vni"] = ntohl(fid.vni.value_())
            dump_fid["nve_ifindex"] = nve_ifindex
            dump_fid["nve_ifname"] = nve_dev.name.string_().decode("utf-8")

        if fid.nve_flood_index_valid.value_():
            dump_fid["nve_flood_index"] = fid.nve_flood_index.value_()

        if family_type_n == "8021Q" or family_type_n == "8021D":
            mid_indexes_dump(fid, dump_fid)

        dump_port_vid_list = []
        dump_fid["port_vid_list"] = dump_port_vid_list
        for port_vid in \
                helpers.list_for_each_entry("struct mlxsw_sp_fid_port_vid",
                                            fid.port_vid_list.address_of_(),
                                            "list"):
                    dump_port_vid = {}
                    dump_port_vid_list.append(dump_port_vid)
                    dump_port_vid["local_port"] = port_vid.local_port.value_()
                    dump_port_vid["vid"] = port_vid.vid.value_()

sys.stdout.write(json.dumps(dump))
