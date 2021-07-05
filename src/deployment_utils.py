import yaml
import logging
import ipaddress

P4_TEMPLATE_APPLY_FLAG = 'VNF_APPLY'
P4_TEMPLATE_APPLY = 'if(meta.function_to_be_executed == {srv6_function_id}) {{\n' \
                    '                    {control_name}.apply(hdr, meta, stdmeta);\n' \
                    '                }}\n                '

P4_TEMPLATE_DEFINITION_FLAG = 'VNF_DEFINITIONS'
P4_TEMPLATE_DEFINITION = '{control_name_up}() {control_name};\n    '

P4_TEMPLATE_INCLUDE_FLAG = 'VNF_INCLUDE'
P4_TEMPLATE_INCLUDE = '#include"{p4_filename}"\n'


P4_MAKEFILE_HEADER = 'all: \n'
P4_MAKEFILE_TEMPLATE = '\tp4c-bm2-ss --arch v1model -o "{filename}.json" --p4runtime-files "{filename}_p4info.txt" "{filename}.p4" \n'


P4_END_NODE_RULE_TERNARY_TEMPLATE = 'table_add ingress.srv6_control.srv6_end set_function_to_be_executed {srv6_local_ip}&&&{mask_node_address} => {priority}\n'
P4_FWD_RULE_TEMPLATE = 'table_add ingress.srv6_control.ipv6_next_hop set_next_hop {srv6_next_hop} => {port_next_hop} {priority}\n'

OF_FWD_RULE_TEMPLATE = "ovs-ofctl add-flow {bridge} dl_type=0x86DD, ipv6_dst={srv6_next_hop}/128, actions=output:{port_next_hop}\n"

OF_ONOS_FWD_RULE_TEMPLATE = {
    'priority': 1,
    'timeout': 0,
    'isPermanent': True,
    'deviceId': '',
    'treatment': {
        'instructions' : [
            {
                'type': 'OUTPUT',
                'port': 0
            }
        ]
    },
    'selector': {
        'criteria': [
            {
                'type': 'ETH_TYPE',
                'ethType': '0x86DD'
            },
            {
                'type': 'IPV6_DST',
                'ip': ""
            }
        ]
    }
}

logger = logging.getLogger(__name__)


def load_allocation_file(in_file):
    with open(in_file, "r") as f:
        allocation = yaml.load(f.read())
    return allocation


def gen_configuration_rules_of(device, device_ip, rules, output_folder):
    # More than rules I should generate the JSON configuration to be POSTED on ONOS REST API
    file_path = output_folder + device + '.cfg'
    logger.info("Writing file %s with the configuration of the device %s OF" % (file_path, device))
    with(open(file_path, mode='w')) as f_config:
        for r in rules:
            f_config.write(OF_FWD_RULE_TEMPLATE.format(
                bridge=device,
                srv6_next_hop="{0:#0{1}x}".format(int(ipaddress.IPv6Address(r['dst_address'])), 32),
                port_next_hop=r['next_hop_port']))
    return file_path



