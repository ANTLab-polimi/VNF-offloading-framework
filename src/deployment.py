import copy
import json
import logging
import ipaddress
from src.TopoManager import TopoManager
from src.deployment_utils import P4_TEMPLATE_APPLY_FLAG, P4_TEMPLATE_DEFINITION_FLAG, P4_TEMPLATE_INCLUDE_FLAG, \
    P4_TEMPLATE_INCLUDE, P4_TEMPLATE_APPLY, P4_TEMPLATE_DEFINITION, P4_MAKEFILE_HEADER, P4_MAKEFILE_TEMPLATE, \
    P4_FWD_RULE_TEMPLATE, P4_END_NODE_RULE_TERNARY_TEMPLATE, OF_ONOS_FWD_RULE_TEMPLATE
from src.config import P4_TEMPLATE_FILE, MASK_NODE_ADDRESS, MASK_FUNCTION_ADDRESS

logger = logging.getLogger(__name__)

# TopoManager
# FunctionsManager
# TrafficManager
# Dict of allocated SFC (traffic demand: (node, uVNF))
# Dict of allocated paths (tr_demand_id: ((SID_1, SID_2):[traversed_nodes])
def generate_deployment_files(topo_mngr, funct_mngr, traffic_mngr, allocated_sfc, allocated_paths, output_folder):
    # Now generate the configuration file for each node.
    # This include the flow rules, P4 programs etc.

    # Now P4 files should be generated
    dict_node_vnf = {}
    # Generate a dict with device as key and as value tuples of tr_demand and vnf deployed for that specific demand
    for (tr_dem, allocation) in allocated_sfc.items():
        for (node, nf) in allocation.items():
            tm = dict_node_vnf.get(node, [])
            tm.extend([(tr_dem, x, y) for (x, y) in nf])
            # tm.extend([(tr_dem, x) for x in nf])
            dict_node_vnf[node] = tm

    # Annotate the allocated VNF with the p4 implementation available in the function library
    dict_node_vnf = funct_mngr.annotate_allocation_with_p4impl(dict_node_vnf)

    # Load P4 template
    with open(P4_TEMPLATE_FILE, mode='r') as f_p4:
        p4_template = f_p4.read()

    # Generate the P4 files for all the node involved in the allocation
    p4_files = gen_p4_files(dict_node_vnf, p4_template)

    # Write the P4 files
    write_p4_files(p4_files, output_folder + "/p4/")

    # Write the Makefile
    write_p4_makefile(p4_files, output_folder + "/p4/")

    # Routing part is needed now
    # I need 2 parts:
    #   1) segments list
    #   2) actual routing between segments

    # Generation of segments and routes (right now the output from the LP model is discarded)
    segment_list, routes = generate_segments_and_routing(traffic_mngr, topo_mngr, allocated_sfc, allocated_paths)

    print_paths_on_topo(allocated_paths, topo_mngr, traffic_mngr, allocated_sfc, output_folder+"/paths_topo/")

    # Generation of the rules for the routing part (dst->next_hop)
    node_rules = gen_rules_for_routing(topo_mngr, routes)

    # Writing to file the segments list and the rules for routing
    with open(output_folder + "/output_segments.json", mode='w') as f:
        f.write(json.dumps(segment_list))
    with open(output_folder + "/output_routes.json", mode='w') as f:
        f.write(json.dumps(routes))
    with open(output_folder + "/output_node_rules.json", mode='w') as f:
        f.write(json.dumps(node_rules))

    # Generate actual configuration for both P4 and OF devices
    list_filename_configurations = generate_actual_p4_of_rules(topo_mngr, node_rules, output_folder)

    # Post the configuration to ONOS for the OF devices
    # TODO: move this to another "main" specialized for doing the deployment part
    # if topo_file is None:
    #     for f in list_filename_configurations['OF']:
    #        topo_mngr.post_new_flows_to_ONOS(f)


def print_paths_on_topo(allocated_paths, topo_mngr, traffic_mngr, allocated_sfc, output_folder):
    # PLOT THE PATHS of the traffic demands
    keys_traffic = list(traffic_mngr.traffic_demands.keys())
    colors = TopoManager.get_random_colors(len(traffic_mngr.traffic_demands))
    dict_colors = {keys_traffic[i]: colors[i] for i in range(len(traffic_mngr.traffic_demands))}
    i = 1
    for (k, d_path) in allocated_paths.items():
        current_path = []
        for (k2, path) in d_path.items():
            current_path.extend(path)
        nodes = list(allocated_sfc[k].keys())
        if len(current_path) > 0:
            topo_mngr.draw_path_on_graph(path=current_path, nodes=nodes, color=dict_colors[k], title=str(k),
                                         filename=output_folder + str(i) + ".png")
        else:
            topo_mngr.draw_path_on_graph(path=current_path, nodes=nodes, color=dict_colors[k],
                                         title=str(k) + "_UNALLOCATED",
                                         filename=output_folder + str(i) + ".png")
        i += 1


def gen_p4_files(dict_allocation, p4_template):
    logger.info('Generating P4 files from the template ...')
    # Pipeconf is also the name of the main control of the VNF
    p4_files = {}
    for (node, allocation) in dict_allocation.items():
        node_p4_template = p4_template
        define_VNF_DEFINITIONS = ''
        define_VNF_APPLY = ''
        define_VNF_INCLUDE = ''
        included_vnfs = []
        for (tr_dem, vnf, ip) in allocation:
            p4_control_name = vnf['pipeconf']
            define_VNF_DEFINITIONS += P4_TEMPLATE_DEFINITION.format(control_name_up=p4_control_name.upper(),
                                                                    control_name=p4_control_name + "_" + str(ip))
            define_VNF_APPLY += P4_TEMPLATE_APPLY.format(srv6_function_id=hex(ip),
                                                         control_name=p4_control_name + "_" + str(ip))
            if vnf['p4_file'] not in included_vnfs:
                define_VNF_INCLUDE += P4_TEMPLATE_INCLUDE.format(p4_filename=vnf['p4_file'])
                included_vnfs.append(vnf['p4_file'])

        node_p4_template = node_p4_template.replace(P4_TEMPLATE_APPLY_FLAG, define_VNF_APPLY)
        node_p4_template = node_p4_template.replace(P4_TEMPLATE_DEFINITION_FLAG, define_VNF_DEFINITIONS)
        node_p4_template = node_p4_template.replace(P4_TEMPLATE_INCLUDE_FLAG, define_VNF_INCLUDE)

        p4_files[str(node) + ".p4"] = node_p4_template
    return p4_files


def write_p4_files(p4_files, output_folder):
    """
    Write the P4 files contained in p4_files dict in the output_folder
    :param p4_files: Dict(p4_filename, p4_content)
    :param output_folder: folder where to put the P4 files
    :return:
    """
    logger.info("Writing P4 files in the folder %s" % output_folder)
    for (p4_filename, p4_content) in p4_files.items():
        logger.info("    Writing %s" % p4_filename)
        with open(output_folder + p4_filename, mode='w') as f_out:
            f_out.write(p4_content)


def write_p4_makefile(p4_files, output_folder, makefile_name='Makefile'):
    logger.info("Writing %s in the folder %s" %
                (makefile_name if makefile_name == 'Makefile' else makefile_name + " makefile", output_folder))
    with(open(output_folder + makefile_name, mode='w')) as f_make:
        f_make.write(P4_MAKEFILE_HEADER)
        for f_name in p4_files.keys():
            logger.debug("    %s" % f_name)
            f_make.write(P4_MAKEFILE_TEMPLATE.format(filename=f_name.split(".")[0]))


def generate_segments_and_routing(trf_mngr, topo_mngr, allocated_sfc, allocated_routes):
    logger.info("Generating segments list and routing... ")
    routes = []
    segment_list = {}  # It will contains all the segments (VNFs nodes with function to traverse) and the destination
    for (k, dem) in trf_mngr.traffic_demands.items():
        logger.info("  Current traffic demand %s" % k)
        allocated_vnf = allocated_sfc.get(k)
        if len(allocated_vnf) == 0:
            logger.info("    Traffic demands not allocated!!")
            continue
        src = dem['src_host']
        dst = dem['dst_host']
        current_sg_list = list(range(sum([len(v) for v in allocated_vnf.values()]) + 2))

        current_sg_list[0] = (topo_mngr.get_hostid_from_ip(src), str(ipaddress.IPv6Address(src)))
        current_sg_list[-1] = (topo_mngr.get_hostid_from_ip(dst), str(ipaddress.IPv6Address(dst)))
        # the items are ordered so the order is also the order in the routing (we used OrderedDict)
        offset = min([e[1] for v in allocated_vnf.values() for e in v])
        for (node, nfs) in allocated_vnf.items():
            node_ip = ipaddress.IPv6Address(topo_mngr.devices[node]['IP'])
            for (n, ip) in nfs:
                function_ip = ipaddress.IPv6Address(ip)
                segment_ip = (node, str(ipaddress.IPv6Address(((int(node_ip) & MASK_NODE_ADDRESS) +
                                                               (int(function_ip) & MASK_FUNCTION_ADDRESS)))))
                current_sg_list[ip - offset + 1] = segment_ip
        segment_list[k] = current_sg_list
        logger.info("      Traffic demand %s has the this segment list: %s" % (k, str(current_sg_list)))

        current_routes = []
        # Now I should generate the routing
        if allocated_routes.get(k, None) is None:
            # Generate the routes only if they are not already present
            allocated_routes[k] = {}
            for i in range(len(current_sg_list) - 1):
                bt_nodes = (current_sg_list[i][0], current_sg_list[i + 1][0], current_sg_list[i + 1][1])
                path_bt_nodes = topo_mngr.shortest_path_between_nodes(bt_nodes[0], bt_nodes[1])
                current_routes.append((bt_nodes, path_bt_nodes))
                allocated_routes[k][(current_sg_list[i][0], current_sg_list[i + 1][0])] = [
                    (path_bt_nodes[i], path_bt_nodes[i + 1]) for i in range(len(path_bt_nodes) - 1)]
        else:
            # If routes are present, generate the route with the corresponding addresses
            for i in range(len(current_sg_list) - 1):
                if current_sg_list[i][0] != current_sg_list[i + 1][0]:
                    # IF its not everything on the same node I should have a path in the allocated_routes
                    bt_nodes = (current_sg_list[i][0], current_sg_list[i + 1][0], current_sg_list[i + 1][1])
                    # Reconstruct the path from the list of links
                    #     # TODO: Is there a better way to do it?
                    next_edge = current_sg_list[i][0]
                    lst_nodes = [current_sg_list[i][0]]
                    while next_edge != current_sg_list[i + 1][0]:
                        for l in allocated_routes[k][(current_sg_list[i][0], current_sg_list[i + 1][0])]:
                            if l[0] == next_edge:
                                next_edge = l[1]
                                break
                        lst_nodes.append(next_edge)
                    current_routes.append((bt_nodes, lst_nodes))
                else:
                    bt_nodes = (current_sg_list[i][0], current_sg_list[i + 1][0], current_sg_list[i + 1][1])
                    current_routes.append((bt_nodes, [current_sg_list[i][0]]))
        logger.info("      Traffic demand %s has the following routing: %s" % (k, str(current_routes)))
        current_routes = []
        # Generate the routes only if they are not already present
        for i in range(len(current_sg_list) - 1):
            bt_nodes = (current_sg_list[i][0], current_sg_list[i + 1][0], current_sg_list[i + 1][1])
            path_bt_nodes = topo_mngr.shortest_path_between_nodes(bt_nodes[0], bt_nodes[1])
            current_routes.append((bt_nodes, path_bt_nodes))
        logger.info("      Traffic demand %s has the following routing: %s" % (k, str(current_routes)))
        routes.extend(current_routes)
    return segment_list, routes


def gen_rules_for_routing(topo_mngr, routes):
    logger.info("Generating the rules for each nodes...")
    node_rules = {}
    for r in routes:
        for i in range(len(r[1]) - 1):
            # Generate rules for routing
            # Check that src is not an host
            if r[1][i] not in topo_mngr.hosts:
                edge_data = topo_mngr.G.get_edge_data(r[1][i], r[1][i + 1])
                rule_to_insert = {'dst_address': r[0][2], 'next_hop_port': edge_data[str(r[1][i]) + '_port']}
                logger.info("  Generated rule on node %s: dst_address->%s, next_hop_port->%s" %
                            (r[1][i], rule_to_insert['dst_address'], rule_to_insert['next_hop_port']))
                try:
                    node_rules[r[1][i]].append(rule_to_insert)
                except KeyError:
                    node_rules[r[1][i]] = [rule_to_insert]
    return node_rules


def gen_configuration_rules_p4(device, device_ip, rules, output_folder):
    priority = 100
    file_path = output_folder + str(device) + '.cfg'
    logger.info("Writing file %s with the configuration of the device %s" % (file_path, device))
    with(open(file_path, mode='w')) as f_config:
        f_config.write(P4_END_NODE_RULE_TERNARY_TEMPLATE.format(
            srv6_local_ip="{0:#0{1}x}".format(int(ipaddress.IPv6Address(device_ip)), 32),
            mask_node_address="{0:#0{1}x}".format(MASK_NODE_ADDRESS, 32),
            priority=priority))
        for r in rules:
            f_config.write(P4_FWD_RULE_TEMPLATE.format(
                srv6_next_hop="{0:#0{1}x}".format(int(ipaddress.IPv6Address(r['dst_address'])), 32),
                port_next_hop=r['next_hop_port'],
                priority=priority))
    return file_path


def gen_configuration_rules_of_ONOS(device, device_ip, rules, output_folder):
    # More than rules I should generate the JSON configuration to be POSTED on ONOS REST API
    file_path = output_folder + str(device) + '_ONOS.json'
    logger.info("Writing file %s with the JSON ONOS configuration of the device %s OF" % (file_path, device))
    json_dict = {'flows': []}
    for r in rules:
        tmp = copy.deepcopy(OF_ONOS_FWD_RULE_TEMPLATE)
        tmp['deviceId'] = device
        tmp['treatment']['instructions'][0]['port'] = int(r['next_hop_port'])
        tmp['selector']['criteria'][1]['ip'] = r['dst_address'] + "/128"
        json_dict['flows'].append(tmp)

    with(open(file_path, mode='w')) as f_config:
        f_config.write(json.dumps(json_dict))
    return file_path


def generate_actual_p4_of_rules(topo_mngr, node_rules, output_folder):
    logger.info("Generation of configuration files...")
    filenames = {'P4': [], 'OF': []}
    for (n, r) in node_rules.items():
        if topo_mngr.is_physical_p4(n) or topo_mngr.is_virtual_p4(n):
            filenames['P4'].append(
                gen_configuration_rules_p4(n, topo_mngr.get_ip_from_deviceid(n), r, output_folder + "/p4/"))
        elif topo_mngr.is_of_ovs(n):
            filenames['OF'].append(gen_configuration_rules_of_ONOS(n, None, r, output_folder + "/of/"))
    return filenames
