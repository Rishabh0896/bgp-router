import json
import sys

from network import IPAddress
from router import RoutingTable


def _create_routing_table_to_debug():
    route_table = RoutingTable()
    route_table.add_route('172.77.0.0', '255.255.0.0', '172.77.0.2', 100, [4], 'EGP', True)
    route_table.add_route('192.0.0.0', '255.0.0.0', '192.0.0.2', 100, [1], 'EGP', True)
    route_table.add_route('192.168.12.0', '255.255.255.0', '192.168.12.2', 100, [3], 'EGP', True)
    route_table.add_route('192.168.0.0', '255.255.0.0', '192.168.0.2', 100, [2], 'EGP', True)
    return route_table


if __name__ == '__main__':
    routing_table = _create_routing_table_to_debug()
    print(routing_table.find_longest_prefix_matches_debug('192.168.0.25'))
