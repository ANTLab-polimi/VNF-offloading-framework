import logging
import random
from src.db_interpreter import load, dump

logger = logging.getLogger(__name__)


class TrafficDemandsManager(object):

    def __init__(self):
        self.birth_death_order = []
        self.traffic_demands = {}

    def load_traffic_demands_from_file(self, traffic_file):
        logger.info("Loading traffic demands...")
        self.traffic_demands = load(traffic_file)

    def save_traffic_demands_to_file(self, traffic_file):
        logger.info("Saving traffic demands...")
        dump(self.traffic_demands, traffic_file)

    def load_birth_death_from_file(self, b_d_file):
        logger.info("Loading birth-death...")
        self.birth_death_order = load(b_d_file)

    def save_birth_death_to_file(self, b_d_file):
        logger.info("Saving birth-death...")
        dump(self.birth_death_order, b_d_file)

    def print_traffic_demands(self, sfc=None):
        if sfc is None or type(sfc) is not dict:
            logger.debug(self.traffic_demands)
            return
        for (k, v) in self.traffic_demands.items():
            logger.debug(str(k) + " " + str(sfc[v['SFC']]))

    def generate_traffic(self, number_of_requests, topo_mngr, traffic=(10, 1000), sfcs=['sfc1'], random_seed=100):
        """
        Generate a given number of random traffic request
        :param number_of_requests:
        :param topo_mngr:
        :param traffic:
        :param sfcs:
        :param random_seed:
        :return:
        """
        random.seed(random_seed)
        logger.info("Generating random traffic demands...")
        index = 0
        while index < number_of_requests:
            tr_demand = self.generate_random_traffic_request(topo_mngr, traffic, sfcs)
            tr_demand["id"] = index
            current_key = tr_demand['src_host'] + "/" + tr_demand['dst_host'] + "/" + tr_demand['SFC']
            self.traffic_demands[index] = tr_demand
            self.birth_death_order.append({'time': 0, 'tr_dem_key': index, 'type': "birth"})
            index += 1
        print(self.traffic_demands)
        logger.info("Generated %i random traffic demands" % number_of_requests)

    def generate_simple_birth_death(self, number_of_requests, topo_mngr, traffic, sfcs, random_seed=100):
        """
        Generate a birth-death of every single traffic demands already loaded or generate with generate_traffic
        :return:
        """
        random.seed(random_seed)
        # i is used to generate the fake times
        i = 0
        index = 0
        while index < number_of_requests:
            tr_demand = self.generate_random_traffic_request(topo_mngr, traffic, sfcs)
            tr_demand["id"] = index
            current_key = tr_demand['src_host'] + "/" + tr_demand['dst_host'] + "/" + tr_demand['SFC']
            self.traffic_demands[index] = tr_demand
            birth_entry = {'time': i, 'tr_dem_key': index, 'type': "birth"}
            death_entry = {'time': i + 1, 'tr_dem_key': index, 'type': "death"}
            self.birth_death_order.append(birth_entry)
            self.birth_death_order.append(death_entry)
            index += 1
            i += 2

    def generate_birth_death_process(self, arrival_rate, average_duration, max_sim_time, topo_mngr, traffic, sfcs,
                                     random_seed):
        """
        Generate a birth-death process for traffic demands for a random SFCs taken from the given pool of SFC.
        Traffic request arrive is a Poisson process with exponentially distributed lifetime.
        :param arrival_rate:
        :param average_duration:
        :param max_sim_time:
        :param topo_mngr:
        :param traffic: [x,y] uniform parameters to generate the amount of traffic requester
        :param sfcs:
        :param random_seed:
        :return:
        """
        random.seed(random_seed)
        next_time = 0
        # b_d_process will contain the ordered events (birth and death)
        # for now just append elements and order afterwards
        # TODO: use bisect package to insert element in order
        b_d_process = []
        # Index to generate unique traffic request
        index = 0
        while next_time < max_sim_time:
            next_time += random.expovariate(arrival_rate / 100)
            duration_time = random.expovariate(1 / average_duration)
            death_time = next_time + duration_time
            # Generate the traffic request.
            tr_dem = self.generate_random_traffic_request(topo_mngr, traffic, sfcs)
            tr_dem["id"] = index
            key = tr_dem['src_host'] + "/" + tr_dem['dst_host'] + "/" + tr_dem['SFC']
            self.traffic_demands[index] = tr_dem
            b_d_process.append({'time': next_time, 'tr_dem_key': index, 'type': "birth"})
            b_d_process.append({'time': death_time, 'tr_dem_key': index, 'type': "death"})
            index += 1
        b_d_process.sort(key=lambda x: x['time'])
        self.birth_death_order = b_d_process

    def generate_only_birth(self, number_of_requests, topo_mngr, traffic, sfcs, random_seed=100):
        random.seed(random_seed)
        for i in range(number_of_requests):
            tr_demand = self.generate_random_traffic_request(topo_mngr, traffic, sfcs)
            tr_demand["id"] = i
            current_key = tr_demand['src_host'] + "/" + tr_demand['dst_host'] + "/" + tr_demand['SFC']
            self.traffic_demands[i] = tr_demand
            birth_entry = {'time': i, 'tr_dem_key': i, 'type': "birth"}
            # in this case in only birth
            self.birth_death_order.append(birth_entry)


    def generate_random_traffic_request(self, topo_mngr, traffic, sfcs):
        logger.info("Generating random traffic demands...")
        sfc = random.choice(sfcs)
        traffic = int(random.uniform(*traffic))
        list_hosts = [h['ipAddresses'][0] for h in topo_mngr.hosts.values()]
        src_host = random.choice(list_hosts)
        list_hosts.remove(src_host)
        dst_host = random.choice(list_hosts)
        return {
            'src_host': src_host,
            'dst_host': dst_host,
            'SFC': sfc,
            'traffic': traffic
        }
