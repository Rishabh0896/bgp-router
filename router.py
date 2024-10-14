import json
import select
import socket
from collections import defaultdict
from typing import List, Dict, Union, Optional, Any, Callable

from network import IPAddress, Network


class RouteEntry:
    """
    Represents a routing entry containing information about the route to a network.

    Attributes:
        next_hop_ip (IPAddress): The IP address of the next hop router.
        local_pref (int): The local preference value for the route.
        as_path (List[int]): The Autonomous System (AS) path to reach the destination.
        origin (str): The origin type of the route (e.g., IGP, EGP).
        self_origin (bool): Whether the route originated from the router itself.
    """

    def __init__(self, next_hop_ip: IPAddress, local_pref: int, as_path: List[int], origin: str, self_origin: bool):
        self.as_path = as_path
        self.next_hop_ip = next_hop_ip
        self.local_pref = local_pref
        self.origin = origin
        self.self_origin = self_origin

    def __str__(self) -> str:
        """
        Returns a detailed string representation of the route entry.

        Returns:
            str: A string displaying all the route attributes.
        """
        return (f"Next Hop: {self.next_hop_ip}, "
                f"Local Pref: {self.local_pref}, "
                f"AS Path: [{' -> '.join(map(str, self.as_path))}], "
                f"Origin: {self.origin}, "
                f"Self Origin: {self.self_origin}")

    def __eq__(self, other) -> bool:
        return (self.as_path == other.as_path and self.next_hop_ip == other.next_hop_ip
                and self.local_pref and other.local_pref and self.origin == other.origin
                and self.self_origin == other.self_origin)


class RoutingTable:
    """
    Represents a routing table that stores route entries for various networks.

    Attributes:
        routes (Dict[Network, List[RouteEntry]]): A dictionary that maps networks to their corresponding route entries.
    """

    def __init__(self):
        """
        Initializes an empty routing table.
        """
        self.routes: Dict[Network, List[RouteEntry]] = defaultdict(list)
        # Save the Network IP and Netmask and Hop_ip as key and the update message as value
        self.update_msgs: Dict[(str, str, str), Dict[str, Any]] = defaultdict(dict)

    def add_route(self, network: str, subnet_mask: str, next_hop_ip: str, local_pref: int,
                  as_path: List[int], origin: str, self_origin: bool) -> None:
        """
        Adds a new route to the routing table.

        Args:
            network (str): The network address.
            subnet_mask (str): The subnet mask.
            next_hop_ip (str): The IP address of the next hop router.
            local_pref (int): The local preference value for the route.
            as_path (List[int]): The AS path to reach the destination.
            origin (str): The origin type of the route.
            self_origin (bool): Whether the route originated from the router itself.
        """
        entry = RouteEntry(IPAddress(next_hop_ip), local_pref, as_path, origin, self_origin)
        network_key = Network(network, subnet_mask)
        self.routes[network_key].append(entry)

        # Check for aggregations
        self.aggregate_networks()

    def get_prefix_length(self, network_ip: str, ip_to_check: str) -> int:
        """
        Calculate the length of the matching prefix between two IP addresses in binary form.

        Args:
            network_ip (str): Binary representation of the network IP.
            ip_to_check (str): Binary representation of the IP to check.

        Returns:
            int: The length of the matching prefix.
        """
        for i, (a, b) in enumerate(zip(network_ip, ip_to_check)):
            if a != b:
                return i
        return len(network_ip)

    def _extract_network_block(self, network: Network) -> str:
        network_ip_binary = network.ip.to_binary()
        network_mask_binary = network.mask.to_binary()
        r1 = ''.join(str(int(a) & int(b)) for a, b in zip(network_ip_binary, network_mask_binary))
        return r1[:network_mask_binary.count('1')]

    def find_longest_prefix_matches(self, ip_string: str) -> List[Network]:
        """
        Find all networks in the routing table that match the given IP address with the longest prefix.

        Args:
            ip_string (str): The IP address to match against.

        Returns:
            List[Network]: A list of Network objects that match the IP with the longest prefix.
        """
        ip_to_check = IPAddress(ip_string)
        ip_to_check_binary = ip_to_check.to_binary()
        matches = []
        longest_prefix = -1

        for network, routes in self.routes.items():
            network_block = self._extract_network_block(network)

            if ip_to_check_binary.startswith(network_block):
                prefix_match = self.get_prefix_length(network.ip.to_binary(), ip_to_check_binary)
                matches.append((network, prefix_match))
                longest_prefix = max(longest_prefix, prefix_match)

        return [network for network, prefix in matches if prefix == longest_prefix]

    def find_best_route(self, ip_string: str) -> Optional[str]:
        """
        Find the best route for the given IP address based on the BGP decision process.

        This method first finds all matching routes with the longest prefix, then applies
        the BGP tie-breaking rules to select the best route among them.

        Args:
            ip_string (str): The IP address to find the best route for.

        Returns:
            Optional[str]: The next hop IP address of the best route, or None if no route is found.
        """
        longest_prefix_matches = self.find_longest_prefix_matches(ip_string)

        if not longest_prefix_matches:
            return None

        best_route = None
        best_route_score = (-float('inf'),) * 5

        for network in longest_prefix_matches:
            for route in self.routes[network]:
                current_score = (
                    route.local_pref,
                    route.self_origin,
                    -len(route.as_path),
                    {'IGP': 2, 'EGP': 1, 'UNK': 0}[route.origin],
                    -route.next_hop_ip.to_int()
                )
                if current_score > best_route_score:
                    best_route_score = current_score
                    best_route = route

        return str(best_route.next_hop_ip) if best_route else None

    def remove_route(self, network_str: str, subnet_mask: str, next_hop_ip: str) -> None:
        """
        Removes a route from the routing table.

        Args:
            network_str (str): The network address to remove.
            subnet_mask (str): The subnet mask of the network.
            next_hop_ip (str): The next hop IP address of the route to remove.
        """
        network_key = Network(network_str, subnet_mask)
        if network_key in self.routes:
            self.routes[network_key] = [route for route in self.routes[network_key]
                                        if str(route.next_hop_ip) != next_hop_ip]
            if not self.routes[network_key]:
                del self.routes[network_key]
        else:
            # Possible aggregation so rebuild the entire routing table based on the update messages
            # Empty the whole routing table and recreate based on the update_msgs dictionary
            self.routes.clear()
            for key, msg in self.update_msgs.items():
                network_ip, network_mask, next_hop_ip = key
                self.add_route(network_ip, network_mask, next_hop_ip, msg['msg']['localpref'], msg['msg']['ASPath'],
                               msg['msg']['origin'], msg['msg']['selfOrigin'])

    def __str__(self) -> str:
        """
        Returns a detailed string representation of the routing table.

        Returns:
            str: A string displaying the routing table with clear formatting.
        """
        if not self.routes:
            return "=== Routing Table: Empty ==="

        table_str = "=" * 80 + "\n"
        table_str += "=== Routing Table ===\n"
        table_str += "=" * 80 + "\n\n"

        for network, entries in self.routes.items():
            table_str += f"Network: {network}\n"
            table_str += "-" * 40 + "\n"
            for i, entry in enumerate(entries, 1):
                table_str += f"  Route {i}:\n"
                table_str += f"    {entry}\n"
            table_str += "\n"

        table_str += "=" * 80 + "\n"
        table_str += "=== End of Routing Table ===\n"
        table_str += "=" * 80 + "\n"

        return table_str

    def can_networks_aggregate(self, network_i, network_j):
        route_i = self.routes[network_i]
        route_j = self.routes[network_j]
        if route_i != route_j:
            return False
        network_block_i = self._extract_network_block(network_i)
        network_block_j = self._extract_network_block(network_j)
        # Check if the last character is different in the network block
        if len(network_block_i) != len(network_block_j):
            return False
        for i in range(len(network_block_i) - 1):
            if network_block_i[i] != network_block_j[i]:
                return False
        if network_block_i[-1] == network_block_j[-1]:
            return False
        return True

    def aggregate_networks(self):
        while True:
            aggregate = False
            # Loop through all the networks present in the routing table
            all_networks = list(self.routes.keys())
            for i in range(len(all_networks)):
                for j in range(i + 1, len(all_networks)):
                    # Compare every two and check if they can be aggregated
                    if self.can_networks_aggregate(all_networks[i], all_networks[j]):
                        # Aggregate network_i and network_j
                        new_netmask = all_networks[i].mask
                        # Convert to binary string
                        binary_mask = new_netmask.octets_to_binary()
                        # Find the position of the last '1' in the binary string
                        last_one_index = binary_mask.rfind('1')

                        modified_binary = binary_mask[:last_one_index] + '0' + binary_mask[last_one_index + 1:]

                        # Convert the modified binary string back to octets
                        new_netmask = IPAddress.binary_to_ip_string(modified_binary)
                        new_network_ip = min(all_networks[i].ip, all_networks[j].ip)
                        new_network = Network(str(new_network_ip), new_netmask)
                        old_route = self.routes[all_networks[i]]
                        # Delete old routes
                        del self.routes[all_networks[i]]
                        del self.routes[all_networks[j]]
                        # Add new aggregated route
                        self.routes[new_network] = old_route
                        aggregate = True
            if not aggregate:
                return

    def dump_table(self) -> List[Dict[str, Union[str, int, List[int], bool]]]:
        """
        Dumps the routing table into a list of dictionaries for serialization or transmission.

        Returns:
            List[Dict[str, Union[str, int, List[int], bool]]]: A list of dictionaries representing the routing table.
        """
        dump = []
        for network, entries in self.routes.items():
            for route in entries:
                row = {
                    'network': str(network.ip),
                    'netmask': str(network.mask),
                    'peer': str(route.next_hop_ip),
                    'localpref': route.local_pref,
                    'ASPath': route.as_path,
                    'selfOrigin': route.self_origin,
                    'origin': route.origin
                }
                dump.append(row)
        return dump


class Router:
    """
    Represents a router with AS number, network connections, and a routing table.

    Attributes:
        asn (int): The Autonomous System number of the router.
        relations (Dict[str, str]): The relationship (customer, peer, provider) with other routers.
        sockets (Dict[str, socket]): The sockets for communication with neighbors.
        ports (Dict[str, int]): The port numbers for each neighboring router.
        update_msgs (List[Dict]): A list of received update messages for the router.
        routing_table (RoutingTable): The router's routing table.
    """
    relations: Dict[str, str] = {}
    sockets: Dict[str, socket.socket] = {}
    ports: Dict[str, int] = {}

    def __init__(self, asn: int, connections: List[str]):
        print("Router at AS %s starting up" % asn)
        self.asn = asn
        self.routing_table = RoutingTable()

        for relationship in connections:
            port, neighbor, relation = relationship.split("-")
            self.sockets[neighbor] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sockets[neighbor].bind(('localhost', 0))
            self.ports[neighbor] = int(port)
            self.relations[neighbor] = relation
            # The started code already sends the handshake messages
            self.send(neighbor,
                      json.dumps({"type": "handshake", "src": self.our_addr(neighbor), "dst": neighbor, "msg": {}}))

    def our_addr(self, dst: str) -> str:
        """
        Generates an IP address with the last octet set to 1.

        Args:
            dst (str): The destination network IP.

        Returns:
            str: The generated IP address.
        """
        quads = list(int(qdn) for qdn in dst.split('.'))
        quads[3] = 1
        return "%d.%d.%d.%d" % (quads[0], quads[1], quads[2], quads[3])

    def send(self, network: str, message: str) -> None:
        """
        Sends a message to a neighboring router.

        Args:
            network (str): The neighboring network.
            message (str): The message to send.
        """
        self.sockets[network].sendto(message.encode('utf-8'), ('localhost', self.ports[network]))

    def advertise_update(self, msg: Dict, source_network: str) -> None:
        """
        Advertises a network path to all neighbors except the one from which the message was received.

        Args:
            msg (Dict): The message containing network path information.
            source_network (str): The network from which the message was received.
        """
        for network in self.sockets:
            if (network != source_network
                    and self.is_transit_allowed(self.relations[source_network], self.relations[network])):
                # Form a new update message here
                update_msg = {"type": "update", "src": self.our_addr(network), "dst": network, "msg": {
                    "network": msg["network"],
                    "netmask": msg["netmask"],
                    "ASPath": [self.asn] + msg["ASPath"],
                }}
                self.sockets[network].sendto(json.dumps(update_msg).encode('utf-8'), ('localhost', self.ports[network]))

    def advertise_withdraw(self, msg: Dict, receive_network: str) -> None:
        for network in self.sockets:
            if (network != receive_network
                    and self.is_transit_allowed(self.relations[receive_network], self.relations[network])):
                # Form a new update message here
                withdraw_msg = {"type": "withdraw", "src": self.our_addr(network), "dst": network, "msg": [{
                    "network": msg[0]["network"],
                    "netmask": msg[0]["netmask"],
                }]}
                self.sockets[network].sendto(json.dumps(withdraw_msg).encode('utf-8'),
                                             ('localhost', self.ports[network]))

    def run(self):
        """
        Main method for the router to continuously listen for incoming messages, process them, and take appropriate
        action.

        The router listens to its sockets and processes the received messages based on their type:
        - 'update': Adds a new route to the routing table and advertises it to other neighbors.
        - 'data': Forwards the data packet to the next hop as determined by the routing table.
        - 'dump': Responds to a request by dumping the entire routing table to the requester.

        The method operates in an infinite loop, polling sockets for incoming data.
        """
        while True:
            socks = select.select(self.sockets.values(), [], [], 0.1)[0]
            for conn in socks:
                k, addr = conn.recvfrom(65535)
                src_network = None
                # self.sockets is a key value pair of network --> socket
                for network in self.sockets:
                    if self.sockets[network] == conn:
                        src_network = network
                        break
                msg = k.decode('utf-8')
                print("Received message '%s' from %s" % (msg, src_network))
                # This is the place where router receives the message
                # Now router has to decide what to do with it
                parsed_msg = json.loads(msg)
                self.process_message(parsed_msg, src_network)

    def process_message(self, parsed_msg: Dict[str, Any], src_network: str):
        """
        Process the received message based on its type.

        Args:
            parsed_msg (Dict[str, Any]): The parsed message.
            src_network (str): The source network of the message.
        """
        message_handlers: Dict[str, Callable[[Dict[str, Any], str], None]] = {
            'update': self.handle_update,
            'data': self.handle_data,
            'dump': self.handle_dump,
            'withdraw': self.handle_withdraw
        }

        msg_type = parsed_msg['type']
        handler = message_handlers.get(msg_type)
        if handler:
            handler(parsed_msg, src_network)
        else:
            print(f"Unknown message type: {msg_type}")

    def handle_update(self, parsed_msg: Dict[str, Any], src_network: str):
        """Handle 'update' message type."""
        self.routing_table.update_msgs[
            (parsed_msg['msg']['network'], parsed_msg['msg']['netmask'], parsed_msg['src'])] = parsed_msg
        self.routing_table.add_route(
            parsed_msg['msg']['network'], parsed_msg['msg']['netmask'],
            parsed_msg['src'], parsed_msg['msg']['localpref'],
            parsed_msg['msg']['ASPath'], parsed_msg['msg']['origin'],
            parsed_msg['msg']['selfOrigin']
        )
        self.advertise_update(parsed_msg['msg'], src_network)

    def handle_data(self, parsed_msg: Dict[str, Any], src_network: str):
        """Handle 'data' message type."""
        dst = parsed_msg['dst']
        next_hop_ip = self.routing_table.find_best_route(dst)
        src_relation = self.relations[src_network]
        dst_relation = self.relations.get(next_hop_ip)

        if next_hop_ip:
            if self.is_transit_allowed(src_relation, dst_relation):
                self.send(next_hop_ip, json.dumps(parsed_msg))
            else:
                self.send_no_route_message(parsed_msg, src_network)
                print("Dropping message")
        else:
            self.send_no_route_message(parsed_msg, src_network)

    def handle_dump(self, parsed_msg: Dict[str, Any], src_network: str):
        """Handle 'dump' message type."""
        dump_response = {
            "type": "table",
            "src": parsed_msg['dst'],
            "dst": parsed_msg['src'],
            "msg": self.routing_table.dump_table()
        }
        self.send(parsed_msg['src'], json.dumps(dump_response))

    def handle_withdraw(self, parsed_msg: Dict[str, Any], src_network: str):
        """Handle 'withdraw' message type."""
        del self.routing_table.update_msgs[
            (parsed_msg['msg'][0]['network'], parsed_msg['msg'][0]['netmask'], parsed_msg['src'])]
        self.routing_table.remove_route(
            parsed_msg['msg'][0]['network'],
            parsed_msg['msg'][0]['netmask'],
            parsed_msg['src']
        )
        self.advertise_withdraw(parsed_msg['msg'], src_network)

    def send_no_route_message(self, parsed_msg: Dict[str, Any], src_network: str):
        """Send a 'no route' message when no route is found."""
        no_route_message = {
            "src": self.our_addr(src_network),
            "dst": src_network,
            "type": "no route",
            "msg": parsed_msg,
        }
        self.send(src_network, json.dumps(no_route_message))

    def is_transit_allowed(self, src_relation: str, dst_relation: str) -> bool:
        """
        Determines if transit is allowed based on the source and destination relationships.

        Args:
            src_relation (str): The relationship with the source network.
            dst_relation (str): The relationship with the destination network.

        Returns:
            bool: True if transit is allowed, False otherwise.
        """
        if src_relation == 'cust' or dst_relation == 'cust':
            return True  # Always allow transit from customers
        return False
