import ipaddress

import matplotlib.pyplot as plt
import networkx as nx
import logging
import json
import copy
import random
import colorsys
import matplotlib.colors as clr
from networkx import to_edgelist

from src.config import DEFAULT_CAPACITY, ONOS_PORT, ONOS_IP
from src.exceptions_definition import AddedException
from src.utils import json_get_req, json_post_req

logger = logging.getLogger(__name__)


class TopoManager(object):

    # Templates for generated topologies
    _templates_hw = [ # Double RMT just because then it is double the probability of appearing inside the network
        {
            'resources': {
                # Extern and match from PSA
                # https://p4.org/p4-spec/docs/PSA-v1.1.0.pdf
                'available_extern': ['ActionProfile', 'ActionSelector', 'Checksum', 'Counter', 'Digest',
                                     'DirectCounter', 'DirectMeter', 'Hash', 'InternetChecksum', 'Meter',
                                     'Random', 'Register'],
                'available_match': ['lpm', 'exact', 'ternary', 'range', 'selector'],
                'pipeline_d': 100,
                'pipeline_w': 50,
                'ORIG_pipeline_d': 100,
                'cpu_capacity': -1
            },
            'dev_type': 'P4_bmv2'
        },
        {
            'resources': {
                # Extern and match from PSA
                # https://p4.org/p4-spec/docs/PSA-v1.1.0.pdf
                'available_extern': ['ActionProfile', 'ActionSelector', 'Checksum', 'Counter', 'Digest',
                                     'DirectCounter', 'DirectMeter', 'Hash', 'InternetChecksum', 'Meter',
                                     'Random', 'Register'],
                'available_match': ['lpm', 'exact', 'ternary', 'range', 'selector'],
                'pipeline_d': 100,
                'pipeline_w': 50,
                'ORIG_pipeline_d': 100,
                'cpu_capacity': -1
            },
            'dev_type': 'P4_bmv2'
        },
        {
            'resources': {
                'available_extern': ['Register', 'Hash', 'Counter', 'Crypto'],
                'available_match': ['Exact', 'ternary', 'lpm'],
                'pipeline_d': 20,
                'ORIG_pipeline_d': 20,
                'pipeline_w': 10,
                'cpu_capacity': -1
            },
            'dev_type': 'P4_bmv2_NIC'
        },
    ]
    _template_sw = {
        'resources': {
            'available_extern': ['ActionProfile', 'ActionSelector', 'Checksum', 'Counter', 'Digest',
                                 'DirectCounter', 'DirectMeter', 'Hash', 'InternetChecksum', 'Meter',
                                 'Random', 'Register', 'Crypto'],
            'available_match': ['lpm', 'exact', 'ternary', 'range', 'selector'],
            'pipeline_d': 100,
            'ORIG_pipeline_d': 100,
            'pipeline_w': 100,
            'cpu_capacity': 10000,
        },
        'dev_type': 'Docker_P4_bmv2'
    }

    _template_sw_UDC = {
        'resources': {
            'available_extern': ['ActionProfile', 'ActionSelector', 'Checksum', 'Counter', 'Digest',
                                 'DirectCounter', 'DirectMeter', 'Hash', 'InternetChecksum', 'Meter',
                                 'Random', 'Register', 'Crypto'],
            'available_match': ['lpm', 'exact', 'ternary', 'range', 'selector'],
            'pipeline_d': 1000000000000,
            'ORIG_pipeline_d': 1000000000000,
            'pipeline_w': 1250,
            'cpu_capacity': 6250,
            'ORIG_cpu_capacity': 6250,
        },
        'dev_type': 'Docker_P4_bmv2'
    }

    _template_sw_DC = {
        'resources': {
            'available_extern': ['ActionProfile', 'ActionSelector', 'Checksum', 'Counter', 'Digest',
                                 'DirectCounter', 'DirectMeter', 'Hash', 'InternetChecksum', 'Meter',
                                 'Random', 'Register', 'Crypto'],
            'available_match': ['lpm', 'exact', 'ternary', 'range', 'selector'],
            'pipeline_d': 1000000000000,
            'ORIG_pipeline_d': 1000000000000,
            'pipeline_w': 10000,
            'cpu_capacity': 50000,
            'ORIG_cpu_capacity': 50000,
        },
        'dev_type': 'Docker_P4_bmv2'
    }
    _annotations_bmv2_nodes = {
        "annotations": {
            "driver": "bmv2",
            "name": "device:bmv2:s2",
            "protocol": "p4runtime",
        }
    }
    _annotations_of_docker_nodes = {
        "driver": "ovs",
        "annotations": {
            "protocol": "OF_13"
        }
    }

    def __init__(self):
        # Fix the seed
        self.G = nx.Graph()
        self.used_nodes = 0
        self.blocked_nodes = 0
        self.pos = None
        self.hosts = {}
        self.devices = {}

    def retrieve_topo_from_ONOS(self, dump=False, folder_dump="./example_files/other/"):
        logger.info("Retrieving Topology...")
        reply = json_get_req('http://%s:%d/onos/v1/devices' % (ONOS_IP, ONOS_PORT))
        if dump:
            with open(folder_dump + "devices.json", mode='w') as f:
                f.write(json.dumps(reply))
        if 'devices' not in reply:
            return
        for dev in filter(lambda x: x['available'] is True, reply['devices']):
            # TODO: fix chassisID in BMv2 device. It is not set.
            # id is 'of:00000000000000a1', chassisID is 'a1'
            # self.G.add_node(dev['id'], type='device')
            self.G.add_node(dev['id'], **dev)
            self.devices[dev['id']] = dev
        reply = json_get_req('http://%s:%d/onos/v1/links' % (ONOS_IP, ONOS_PORT))
        if dump:
            with open(folder_dump + "links.json", mode='w') as f:
                f.write(json.dumps(reply))
        if 'links' not in reply:
            return
        for link in reply['links']:
            n1 = link['src']['device']
            n2 = link['dst']['device']
            if 'annotations' in link and 'bandwidth' in link['annotations']:
                    bw = int(link['annotations']['bandwidth']) * 1e6
            else:
                bw = DEFAULT_CAPACITY
            n1_port = link['src']['port']
            n2_port = link['dst']['port']
            self.G.add_edge(n1, n2, **{'bandwidth': bw, n1+'_port': n1_port, n2+'_port': n2_port})

        # pdb.set_trace()

        reply = json_get_req('http://%s:%d/onos/v1/hosts' % (ONOS_IP, ONOS_PORT))
        if dump:
            with open(folder_dump + "hosts.json", mode='w') as f:
                f.write(json.dumps(reply))
        if 'hosts' not in reply:
            return
        for host in reply['hosts']:
            host.update({'type': 'host', 'ip': host['ipAddresses'][0]})
            self.G.add_node(host['id'], **host)
            for location in host['locations']:
                self.G.add_edge(host['id'], location['elementId'],
                                **{'bandwidth': DEFAULT_CAPACITY,
                                   location['elementId'] + '_port': location['port'], host['id'] + '_port': -1})
            self.hosts[host['id']] = host
        self.G = nx.to_directed(self.G)
        self.pos = nx.fruchterman_reingold_layout(self.G)

    def retrieve_topo_from_files(self, devices_file, links_file, hosts_file):
        logger.info("Loading Topology...")

        with open(devices_file, mode='r') as f_d:
            reply = json.loads(f_d.read())
        if 'devices' not in reply:
            return
        for dev in filter(lambda x: x['available'] is True, reply['devices']):
            # TODO: fix chassisID in BMv2 device. It is not set.
            # id is 'of:00000000000000a1', chassisID is 'a1'
            self.G.add_node(dev['id'], **dev)
            self.devices[dev['id']] = dev

        with open(links_file, mode='r') as f_l:
            reply = json.loads(f_l.read())
        if 'links' not in reply:
            return
        for link in reply['links']:
            n1 = link['src']['device']
            n2 = link['dst']['device']
            if 'annotations' in link and 'bandwidth' in link['annotations']:
                bw = int(link['annotations']['bandwidth']) * 1e6
            else:
                bw = DEFAULT_CAPACITY
            n1_port = link['src']['port']
            n2_port = link['dst']['port']
            self.G.add_edge(n1, n2, **{'bandwidth': bw, n1+'_port': n1_port, n2+'_port': n2_port})

        # reply = json_get_req('http://%s:%d/onos/v1/hosts' % (ONOS_IP, ONOS_PORT))
        with open(hosts_file, mode='r') as f_h:
            reply = json.loads(f_h.read())

        if 'hosts' not in reply:
            return
        for host in reply['hosts']:
            host.update({'type': 'host', 'ip': host['ipAddresses'][0]})
            self.G.add_node(host['id'], **host)
            for location in host['locations']:
                self.G.add_edge(host['id'], location['elementId'],
                                **{'bandwidth': DEFAULT_CAPACITY,
                                   location['elementId']+'_port': location['port'], host['id']+'_port': -1})
            self.hosts[host['id']] = host
        self.G = nx.to_directed(self.G)
        self.pos = nx.fruchterman_reingold_layout(self.G)

    def read_from_gml(self, path, templates_hw=_templates_hw, template_sw=_template_sw,
                      p_hw_nodes=0.6, p_att_docker_nodes=0.2, p_of_nodes=0.2, n_docker_nodes=(1, 5), random_seed=100):
        random.seed(random_seed)
        assert p_hw_nodes+p_att_docker_nodes+p_of_nodes == 1, \
            'Sum of percentage of various type of nodes should be 1 (hw=%.2f, dk=%.2f, of=%.2f)' % \
            (p_hw_nodes, p_att_docker_nodes, p_of_nodes)
        logger.info("Loading GML topology file from %s..." % path)
        base_address_hosts = ipaddress.IPv6Address("2000::1")
        base_address_devices = ipaddress.IPv6Address("4000::1")

        # Read the respective GML file
        self.G = nx.read_gml(path)#, label='id')

        n_nodes = self.G.number_of_nodes()
        n_hw_nodes = round(n_nodes*p_hw_nodes)
        n_att_docker_nodes = round(n_nodes*p_att_docker_nodes)
        n_of_nodes = n_nodes-n_hw_nodes-n_att_docker_nodes
        logger.info("    Total devices: %i" % n_nodes)
        logger.info("        HW                  %4i (%.2f%%)" % (n_hw_nodes, p_hw_nodes*100))
        logger.info("        W/ DOCKER ATTACHED  %4i (%.2f%%)" % (n_att_docker_nodes, p_att_docker_nodes*100))
        logger.info("        OF                  %4i (%.2f%%)" % (n_of_nodes, p_of_nodes*100))

        assert n_hw_nodes+n_att_docker_nodes+n_of_nodes == n_nodes, \
            'Sum of the number of different types of nodes should be the total number of nodes (%i+%i+%i!=%i)' % \
            (n_hw_nodes, n_att_docker_nodes, n_of_nodes, n_nodes)

        # Now we need to generate the random assignment of SW and HW nodes
        hw_nodes = random.sample(self.G.nodes, n_hw_nodes)
        att_docker_nodes = random.sample(self.G.nodes - hw_nodes, n_att_docker_nodes)
        of_nodes = list(self.G.nodes - (hw_nodes + att_docker_nodes))

        # Host attached on all hw and OF nodes
        mac_addr = 1 # Definition of the base mac address to generate all the other
        bw = DEFAULT_CAPACITY
        cnt = 0
        for h in hw_nodes+of_nodes:
            cnt += 1
            host_id = self.int_to_mac(mac_addr) + "/none"
            current_host = {
                'id': host_id,
                'mac': self.int_to_mac(mac_addr),
                'ip': str(base_address_hosts),
                'ipAddresses': [str(base_address_hosts)],
                'locations': [
                    {'elementId': h}
                ],
                'type': 'host'
            }
            mac_addr += 1
            base_address_hosts += 1
            self.hosts[host_id] = current_host
            self.G.add_node(host_id, **current_host)
            self.G.add_edge(h, host_id)
            logger.info("    Added %i host nodes" % cnt)
        # Generate annotations and resources for all the other nodes
        for d in hw_nodes:
            current_device = {
                'id': d,
                'type': 'SWITCH',
                'IP': str(base_address_devices),
                'blocked': False,
                'dont_use': False
            }
            base_address_devices += 1
            # annotate the device with resources
            current_template = random.choice(templates_hw)
            current_device.update(copy.deepcopy(current_template))
            current_device.update(self._annotations_bmv2_nodes)
            self.devices[d] = current_device
            self.G.node[d].update(current_device)
            logger.info("    Annotated %i BMv2 HW nodes with %s" % (len(hw_nodes), str(current_template)))

        cnt = 0
        for d in att_docker_nodes:
            actual_docker_nodes = int(random.uniform(*n_docker_nodes))
            cnt += actual_docker_nodes
            # Create the docker nodes attached to the d node
            new_docker_nodes = [{'id': str(d)+"_docker_"+str(i), 'type': 'SWITCH', **copy.deepcopy(template_sw)} for i in range(actual_docker_nodes)]
            # Add the IP to the docker nodes created
            [new_docker_nodes[i].update({'IP': base_address_devices+i}) for i in range(len(new_docker_nodes))]
            base_address_devices += len(new_docker_nodes)
            self.devices.update({el['id'] : el for el in new_docker_nodes})
            [self.G.add_node(el['id'], **el) for el in new_docker_nodes]
            [self.G.add_edge(d, el['id']) for el in new_docker_nodes]

            # Annotate correctly the current device
            current_device = {
                'id': d,
                'type': 'SWITCH',
                'IP': str(base_address_devices),
                'blocked': False,
                'dont_use': False
            }
            base_address_devices += 1
            current_device.update(self._annotations_of_docker_nodes)
            self.devices[d] = current_device
            self.G.node[d].update(current_device)
        logger.info("    Added %i BMv2 docker" % cnt)
        logger.info("    Annotated %i BMv2 docker with %s" % (cnt, str(template_sw)))

        for d in of_nodes:
            current_device = {
                'id': d,
                'type': 'SWITCH',
                'IP': str(base_address_devices),
                'blocked': False,
                'dont_use': False
            }
            base_address_devices += 1
            current_device.update(self._annotations_of_docker_nodes)
            self.devices[d] = current_device
            self.G.node[d].update(current_device)
        logger.info("    Annotated %i node with OF characteristics" % (len(att_docker_nodes)+len(of_nodes)))
        logger.info("    Fixing port on the edges")
        nodes_port = {el:0 if self.G.nodes[el]['type'] != 'host' else -1 for el in self.G.nodes}
        for e in self.G.edges:
            n1 = e[0]
            n2 = e[1]
            n1_port = nodes_port[n1]
            if n1_port != -1:
                nodes_port[n1] += 1
            n2_port = nodes_port[n2]
            if n2_port != -1:
                nodes_port[n2] += 1

            self.G.edges[e].update({
                str(n1)+'_port': n1_port,
                str(n2)+'_port': n2_port,
                'bandwidth': bw
            })
        self.G = nx.to_directed(self.G)
        self.pos = nx.fruchterman_reingold_layout(self.G)
        logger.info("Topology %s loaded" % path.split("/")[-1])

    def load_from_yaml_nx(self, yaml_file):
        self.G = nx.read_yaml(yaml_file)
        self.G = nx.to_directed(self.G)
        self.hosts = {k: self.G.node[k] for k in filter(lambda x: self.G.node[x]['type'] == 'host', self.G.node.keys())}
        self.devices = {self.G.node[k]['id']: self.G.node[k] for k in filter(lambda x: self.G.node[x]['type'] == 'SWITCH', self.G.node.keys())}
        self.pos = nx.fruchterman_reingold_layout(self.G)

    def save_to_yaml_nx(self, yaml_file):
        if not yaml_file.endswith(".yaml"):
            logger.warning("Writing YAML to file without .yaml extension")
        nx.write_yaml(self.G, yaml_file)

    def annotate_graph_with_resources(self, resources_db):
        logger.info("Annotating graph with resources...")
        for res in resources_db:
            if res['id'] in self.G.node:
                # Add annotation on networkX object and on local object
                self.G.node[res['id']]['resources'] = res['resources']
                self.G.node[res['id']]['IP'] = res['IP']
                self.G.node[res['id']]['dev_type'] = res['type']
                self.G.node[res['id']]['blocked'] = False
                self.G.node[res['id']]['dont_use'] = False
                self.devices[res['id']]['resources'] = res['resources']
                self.devices[res['id']]['IP'] = res['IP']
                self.devices[res['id']]['dev_type'] = res['type']
                self.devices[res['id']]['blocked'] = False
                self.devices[res['id']]['dont_use'] = False
            else:
                logger.error("Node %s in the database of the resource is not available in the network" % res['id'])

    def draw_topo(self, title=None, block=True, filename=None):
        logger.info("Drawing topology graph...")
        plt.figure(figsize=[6.4*2, 4.8*2])

        # Draw Hosts (green pentagon)
        nx.draw_networkx_nodes(self.G, self.pos, nodelist=self.hosts, node_shape='p', node_color='g')

        # Draw physical P4 devices (NIC and Switches) (purple square)
        nx.draw_networkx_nodes(self.G, self.pos,
                               nodelist={d: self.devices[d] for d in filter(lambda x: self.is_physical_p4(x), self.devices.keys())},
                               node_shape='s', node_color='purple')

        # Draw virtual P4 devices (docker) (yellow circle)
        nx.draw_networkx_nodes(self.G, self.pos,
                               nodelist={d: self.devices[d] for d in filter(lambda x: self.is_virtual_p4(x), self.devices.keys())},
                               node_shape='o', node_color='y')

        # Draw "legacy" OF switches (include also OVS for dockers) (grey square)
        nx.draw_networkx_nodes(self.G, self.pos,
                               nodelist={d: self.devices[d] for d in filter(lambda x: self.is_of_ovs(x), self.devices.keys())},
                               node_shape='s', node_color='grey')

        nx.draw_networkx_labels(self.G.subgraph(self.hosts), self.pos,
                                labels={h: self.G.node[h]['ip']
                                        for h in filter(lambda x: self.G.node[x]['type'] == 'host', self.G.node.keys())},
                                font_color='k')

        nx.draw_networkx_labels(self.G.subgraph(self.devices), self.pos, font_color='k')
        nx.draw_networkx_edges(self.G, self.pos, edge_color='k')
        plt.xticks([])
        plt.yticks([])
        plt.title(title)

        if filename:
            logger.info("Draw topology to file: " + filename)
            plt.savefig(filename)
        else:
            plt.show(block=block)

    def draw_path_on_graph(self, path, nodes, title=None, color='r', block=True, filename=None):
        logger.info("Drawing path on topology graph...")
        if not all(i in self.G.edges for i in path):
            logger.error("    ERROR: Path is not part of the graph!!")
            return
        if not all(i in self.G.node for i in nodes):
            logger.error("    ERROR: Some nodes are not part of the graph!!")
            return
        tmp_graph = nx.DiGraph()
        tmp_graph.add_nodes_from(self.G.graph)
        tmp_graph.add_edges_from(path)
        plt.figure(figsize=[6.4 * 2, 4.8 * 2])
        # Draw Hosts (green pentagon)
        nx.draw_networkx_nodes(self.G, self.pos, nodelist=self.hosts, node_shape='p', node_color='g')

        # Draw physical P4 devices (NIC and Switches) (purple square)
        nx.draw_networkx_nodes(self.G, self.pos,
                               nodelist={d: self.devices[d] for d in
                                         filter(lambda x: self.is_physical_p4(x), self.devices.keys())},
                               node_shape='s', node_color='purple')

        # Draw virtual P4 devices (docker) (yellow circle)
        nx.draw_networkx_nodes(self.G, self.pos,
                               nodelist={d: self.devices[d] for d in
                                         filter(lambda x: self.is_virtual_p4(x), self.devices.keys())},
                               node_shape='o', node_color='y')

        # Draw "legacy" OF switches (include also OVS for dockers) (grey square)
        nx.draw_networkx_nodes(self.G, self.pos,
                               nodelist={d: self.devices[d] for d in
                                         filter(lambda x: self.is_of_ovs(x), self.devices.keys())},
                               node_shape='s', node_color='grey')
        nx.draw_networkx_labels(self.G.subgraph(self.hosts),
                                self.pos,
                                labels={h: self.G.node[h]['ip']
                                        for h in
                                        filter(lambda x: self.G.node[x]['type'] == 'host', self.G.node.keys())},
                                font_color='k')
        nx.draw_networkx_labels(self.G.subgraph(self.devices), self.pos, font_color='k')
        nx.draw_networkx_edges(self.G, self.pos, edge_color='k')

        # Add on top of the current graph the selected path and nodes
        nx.draw_networkx_edges(tmp_graph, self.pos, edge_color=color, width=3, arrowstyle='->', arrowsize=30)
        nx.draw_networkx_nodes(self.G, self.pos, nodelist=nodes, node_shape="P", node_color=color, node_size=500)

        plt.xticks([])
        plt.yticks([])
        plt.title(title)

        if filename:
            logger.info("Draw path to file: " + filename)
            plt.savefig(filename)
            plt.close()
        else:
            plt.show(block=block)

    def ordered_paths_between_nodes(self, id_src, id_dst, order_key=lambda s: len(s), reverse=False):
        # Simple path are not enough to pass through the virtual nodes.
        # Virtual nodes will be added when the current path in the analysis is not sufficient to contain the SFC
        shortest_paths = list(nx.all_simple_paths(self.G, id_src, id_dst))
        # Sort paths in lengths
        shortest_paths.sort(key=order_key, reverse=reverse)
        logger.debug(shortest_paths)
        return shortest_paths

    def shortest_path_between_nodes(self, id_src, id_dst):
        return nx.shortest_path(self.G, id_src, id_dst)

    def extend_path_with_virtual_node(self, path):
        new_path = copy.deepcopy(path)
        try:
            # Try to extend the path on each node in the entire path
            for (i, n) in enumerate(new_path):
                if n not in self.hosts:
                    # Get the neighbors of the current node (exclude the hosts from beginning)
                    neigh = self.G.neighbors(n)
                    for x in neigh:
                        # Check if one of the node in the neighbors is a virtual P4 node
                        if self.is_virtual_p4(x):
                            # Current node is a node with virtual resources available,
                            # add the link from and to this node
                            new_path.insert(i, n)
                            new_path.insert(i + 1, x)
                            # Raise exception to break the 2 nested cycles
                            raise AddedException()
            return None
        except AddedException:
            logger.info("   Extended path: " + str(new_path))
            return new_path

    def remove_edge_from_graph(self, seed=100, n=2):
        random.seed()
        # TODO: check if this removed edge will create a node to be disconnected from the graph
        edge_to_remove = random.sample(self.G.edges(), k=n)
        print(edge_to_remove)
        self.G.remove_edges_from(edge_to_remove)

    def get_hostid_from_ip(self, ip):
        try:
            return list(filter(lambda x: ip in x['ipAddresses'], self.hosts.values()))[0]['id']
        except IndexError:
            logger.error("No host with specified IP %s" % ip)
            return None

    def get_ip_from_deviceid(self, dev_id):
        return self.devices[dev_id]['IP']

    def post_new_flows_to_ONOS(self, config_file):
        with open(config_file, mode='r') as f:
            logger.info(json_post_req('http://%s:%d/onos/v1/flows' % (ONOS_IP, ONOS_PORT), f.read()))

    def is_p4(self, device):
        return self.is_physical_p4(device) or self.is_virtual_p4(device)

    def is_virtual_p4(self,  device):
        """
        Check if the passed device ID is of a virtual P4 node (a docker P4 node)
        :param device:
        :return:
        """
        return 'dev_type' in self.G.nodes[device].keys() and self.G.nodes[device]['dev_type'] == 'Docker_P4_bmv2'

    def is_physical_p4(self, device):
        """
        Check if the passed device ID is of a physical P4 node (BMv2 switch of smartNIC)
        :param device:
        :return:
        """
        return 'dev_type' in self.G.nodes[device].keys() and (self.G.nodes[device]['dev_type'] == 'P4_bmv2' or
                                                              self.G.nodes[device]['dev_type'] == 'P4_bmv2_NIC')

    def is_of_ovs(self, device):
        """
        Return true if the device is an OVS switch (OpenFlow)
        :param device:
        :return:
        """
        return 'driver' in self.devices[device] and self.devices[device]['driver'] == 'ovs'

    def reduce_resources_on_node(self, node_id, uvnf, traffic=0):
        """
        Remove the resources of the uvnf from the specified node. CPU resource needed is the pipeline_depth * traffic
        :param node:
        :param uvnf:
        :param traffic:
        :return:
        """
        if self.G.node[node_id]['resources']['pipeline_d'] == self.G.node[node_id]['resources']['ORIG_pipeline_d']:
            self.used_nodes += 1
        self.G.node[node_id]['resources']['pipeline_d'] -= uvnf['requirements']['depth']
        # Reduce CPU resource of virtual nodes
        if self.is_virtual_p4(node_id):
            self.G.node[node_id]['resources']['cpu_capacity'] -= uvnf['requirements']['depth'] * traffic

    def restore_resources_on_node(self, node_id, uvnf, traffic=0):
        """
        Restore the resources used by the uvnf on the given node. CPU resource needed is the pipeline_depth * traffic
        :param node_id:
        :param uvnf:
        :param traffic:
        :return:
        """
        self.G.node[node_id]['resources']['pipeline_d'] += uvnf['requirements']['depth']
        if self.G.node[node_id]['resources']['pipeline_d'] == self.G.node[node_id]['resources']['ORIG_pipeline_d']:
            self.used_nodes -= 1
        # Reduce CPU resource of virtual nodes
        if self.is_virtual_p4(node_id):
            self.G.node[node_id]['resources']['cpu_capacity'] += uvnf['requirements']['depth'] * traffic

    def block_node(self, node_id):
        """
        Make a node blocked, in this way it won't be used anymore for deploying functions
        :param node_id:
        :return:
        """
        # Block only NON virtual nodes
        if self.is_physical_p4(node_id):
            if self.G.node[node_id]['blocked']:
                logger.error("Trying to lock an already locked node!!!")
                return False
            self.G.node[node_id]['blocked'] = True
            self.blocked_nodes += 1
            return True
        else:
            logger.warning("Trying to block a NON physical node!")
            return False

    def is_blocked(self, node_id):
        # Check that field 'blocked' exists, if so return that value, otherwise return False because the node is an Host or OF device
        return self.G.node[node_id]['blocked'] if 'blocked' in self.G.node[node_id].keys() else False

    def is_dont_use(self, node_id):
        # Check that field 'dont_use' exists, if so return that value, otherwise return False because the node is an Host or OF device
        return self.G.node[node_id]['dont_use'] if 'dont_use' in self.G.node[node_id].keys() else False

    def unlock_node(self, node_id):
        """
        Unlock a node, from now on the node can be used to deploy network functions
        :param node_id:
        :return:
        """
        if 'blocked' in self.G.node[node_id].keys():
            if not self.G.node[node_id]['blocked']:
                logger.error("Trying to unlock an already unlocked node!!")
                return
            self.G.node[node_id]['blocked'] = False
            self.blocked_nodes -= 1

    def dont_use_node(self, node_id):
        if 'dont_use' in self.G.node[node_id].keys():
            self.G.node[node_id]['blocked'] = True
        else:
            logger.warning("Trying to block a NON physical node!")

    def make_usable(self, node_id):
        if 'dont_use' in self.G.node[node_id].keys():
            self.G.node[node_id]['blocked'] = False

    def n_of_devices(self):
        return len(list(filter(lambda elem: self.is_of_ovs(elem["id"]), self.devices.values())))

    def n_p4_devices(self):
        return len(list(filter(lambda elem: self.is_p4(elem["id"]), self.devices.values())))

    def n_devices(self):
        return len(self.devices)

    def n_hosts(self):
        return len(self.hosts)

    @staticmethod
    def get_random_colors(n):
        random.seed(100)
        colors = []
        for i in range(n):
            h, s, l = random.random(), 0.5 + random.random() / 2.0, 0.4 + random.random() / 5.0
            c = [i for i in colorsys.hls_to_rgb(h, l, s)]
            colors.append(clr.to_hex(c))
        return colors

    @staticmethod
    def int_to_mac(mac_addr):
        mac_hex = "{:012x}".format(mac_addr)
        return ":".join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))

map_str_to_templates = {
    "sw_UDC": TopoManager._template_sw_UDC,
    "sw_DC": TopoManager._template_sw_DC,
    "hw": TopoManager._templates_hw
}