import logging
import random
import copy
from src.db_interpreter import load, dump

logger = logging.getLogger(__name__)


class FunctionsManager(object):

    # Possible extern and match from PSA
    # https://p4.org/p4-spec/docs/PSA-v1.1.0.pdf
    _possible_extern = ['ActionProfile', 'ActionSelector', 'Checksum', 'Counter', 'Digest', 'DirectCounter',
                        'DirectMeter',
                        'Hash', 'InternetChecksum', 'Meter', 'Random', 'Register']
    _possible_match = ['lpm', 'exact', 'ternary', 'range', 'selector']

    # -------------------- TEMPLATES ------------------------------------------
    _template_function = {
        'VNF': 'name_monolithic',
        'implementations': []
    }
    _template_implementation = {
        'impl_name': 'impl_name',
        'VNF_composition': []
    }
    _template_uvnf = {
        'VNF': 'name_uVNF',
        'p4_file': 'path_p4_file',
        'pipeconf': 'pipeconf_name',
        'configuration': 'configuration_file',
        'requirements': {
            'extern': [],
            'match': [],
            'depth': 0,
            'width': 0,
        }
    }

    def __init__(self):
        self.functions = {}

    def load_functions_from_file(self, functions_file):
        logger.info("Loading functions description...")
        tmp_functions = load(functions_file)
        for vnf in tmp_functions:
            if vnf['VNF'] in self.functions.keys():
                raise Exception('VNF %s is duplicate' % vnf['VNF'])
            self.functions[vnf['VNF']] = vnf

    def save_functions_to_file(self, functions_file):
        logger.info("Saving functions to file...")
        dump(list(self.functions.values()), functions_file, json_i=False)

    def annotate_sfc_with_functions(self, sfcs):
        logger.info("Annotating SFC with functions implementations...")
        if type(sfcs) is list:
            for sfc in sfcs:
                for vnf in sfc['VNFs']:
                    current_vnf_name = vnf['VNF']
                    if current_vnf_name in self.functions.keys():
                        lst_supported_impls = []
                        if 'all' in vnf['supported_impls']:
                            # all implementations supported
                            lst_supported_impls = self.functions[current_vnf_name]['implementations']
                        else:
                            for impl in vnf['supported_impls']:
                                # put just the supported implementations
                                current_impl = list(filter(lambda x: impl == x['impl_name'],
                                                           self.functions[current_vnf_name]['implementations']))
                                lst_supported_impls.extend(current_impl)
                                if len(current_impl) == 0:
                                    logger.warning("%s does not correspond to any implementation on the functions database"
                                                   % impl)
                        vnf['implementations'] = lst_supported_impls
                    else:
                        raise Exception('VNF %s of SFC %s is not available in the functions database' %
                                        (current_vnf_name, sfc['name']))
                    try:
                        del vnf["supported_impls"]
                    except KeyError:
                        logger.info("supported_impls field not available on %s VNF" % current_vnf_name)
            return sfcs
        elif type(sfcs) is dict:
            for (k, sfc) in sfcs.items():
                for vnf in sfc['VNFs']:
                    current_vnf_name = vnf['VNF']
                    if current_vnf_name in self.functions.keys():
                        lst_supported_impls = []
                        if 'all' in vnf['supported_impls']:
                            # all implementations supported
                            lst_supported_impls = self.functions[current_vnf_name]['implementations']
                        else:
                            for impl in vnf['supported_impls']:
                                # put just the supported implementations
                                current_impl = list(filter(lambda x: impl == x['impl_name'],
                                                           self.functions[current_vnf_name]['implementations']))
                                lst_supported_impls.extend(current_impl)
                                if len(current_impl) == 0:
                                    logger.warning("%s does not correspond to any implementation on the functions database"
                                                   % impl)
                        vnf['implementations'] = lst_supported_impls
                    else:
                        raise Exception('VNF %s of SFC %s is not available in the functions database' %
                                        (current_vnf_name, sfc['name']))
                    try:
                        del vnf["supported_impls"]
                    except KeyError:
                        logger.info("supported_impls field not available on %s VNF" % current_vnf_name)
            return sfcs

    def find_VNF_impl(self, vnf_name):
        """
        Return the VNF implementation description from the VNF name
        :param vnf_name: the name of the VNF you want to retrieve the implementation description
        :return: VNF implementation description
        """
        for (k, v) in self.functions.items():
            for vnf_impl in v['implementations']:
                for vnf in vnf_impl['VNF_composition']:
                    # Here I have all the implementation, the name if the field VNF
                    if vnf['VNF'] == vnf_name:
                        return vnf
        return None

    def annotate_allocation_with_p4impl(self, dict_allocation):
        logger.info("Annotating allocation with specific VNF implementation...")
        for (node, allocation) in dict_allocation.items():
            new_tr_dem_vnf = []
            for (tr_dem, vnf, ip) in allocation:
                impl_desc = self.find_VNF_impl(vnf)
                if impl_desc is None:
                    raise Exception(
                        "VNF %s is not present as implementation in the database of functions" % (vnf))
                new_tr_dem_vnf.append((tr_dem, impl_desc, ip))
            dict_allocation[node] = new_tr_dem_vnf
        return dict_allocation

    def generate_random_functions(self,
                                  number_vnfs,
                                  n_implementations=(1, 10),
                                  n_microvnfs=(1, 10),
                                  n_externs=(1, int(len(_possible_extern) / 2)), n_match=(1, int(len(_possible_match))),
                                  depth=(1, 32),
                                  width=(1, 5),
                                  random_seed=100):
        logger.info("Generating random functions...")
        random.seed(random_seed)
        for i in range(number_vnfs):
            new_vnf = copy.deepcopy(self._template_function)
            new_vnf['VNF'] = 'vnf_' + str(i)

            # Generate the monolithic definition of the implementation
            new_vnf['implementations'].append(copy.deepcopy(self._template_implementation))
            new_vnf['implementations'][0]['impl_name'] = new_vnf['VNF'] + "_impl_0"

            # Generate the monolithic definition of the VNF
            base_uvnf = copy.deepcopy(self._template_uvnf)
            base_uvnf['VNF'] = new_vnf['implementations'][0]['impl_name'] + '_dec_0'
            base_uvnf['requirements']['extern'] = random.sample(self._possible_extern, random.randint(*n_externs))
            base_uvnf['requirements']['match'] = random.sample(self._possible_match, random.randint(*n_match))
            base_uvnf['requirements']['depth'] = random.randint(*depth)
            base_uvnf['requirements']['width'] = random.randint(*width)

            new_vnf['implementations'][0]['VNF_composition'].append(base_uvnf)

            # Generate the other implementations
            for n in range(random.randint(*n_implementations)):
                new_implementation = copy.deepcopy(self._template_implementation)
                new_implementation['impl_name'] = new_vnf['VNF'] + "_impl_" + str(n + 1)
                # Generate all the micro VNF that compose the current implementation
                for x in range(random.randint(*n_microvnfs)):
                    new_uvnf = copy.deepcopy(self._template_uvnf)
                    new_uvnf['VNF'] = new_implementation['impl_name'] + '_dec_' + str(x)
                    # Take at random the externs and matches from the monolithic implementation
                    # TODO: should be sure that all the extern and match are included in the microVNFs?
                    new_uvnf['requirements']['extern'] = random.sample(base_uvnf['requirements']['extern'],
                                                                       random.randint(1, len(
                                                                           base_uvnf['requirements']['extern'])))
                    new_uvnf['requirements']['match'] = random.sample(base_uvnf['requirements']['match'],
                                                                      random.randint(1, len(
                                                                          base_uvnf['requirements']['match'])))
                    # TODO: should the sum of all the depths be <= of the base monolithic version?
                    new_uvnf['requirements']['depth'] = random.randint(1, base_uvnf['requirements']['depth'])
                    new_uvnf['requirements']['width'] = random.randint(1, base_uvnf['requirements']['width'])
                    new_implementation['VNF_composition'].append(new_uvnf)

                new_vnf['implementations'].append(new_implementation)
            self.functions[new_vnf['VNF']] = new_vnf
