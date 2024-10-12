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


class RoutingTable:
    """
    Represents a routing table that stores route entries for various networks.

    Attributes:
        routes (Dict[Network, RouteEntry]): A dictionary that maps networks to their corresponding route entries.
    """

    def __init__(self):
        self.routes: Dict[Network, List[RouteEntry]] = defaultdict(list)

    def add_route(self, network: str, subnet_mask: str, next_hop_ip: str, local_pref: int,
                  as_path: List[int], origin: str, self_origin: bool) -> None:
        """
        Adds a new route to the routing table.

        Args:
            network (str): The network address.
            subnet_mask (str): The subnet mask.
            next_hop_ip (IPAddress): The IP address of the next hop router.
            local_pref (int): The local preference value for the route.
            as_path (List[int]): The AS path to reach the destination.
            origin (str): The origin type of the route.
            self_origin (bool): Whether the route originated from the router itself.
        """
        entry = RouteEntry(IPAddress(next_hop_ip), local_pref, as_path, origin, self_origin)
        network_key = Network(network, subnet_mask)
        self.routes[network_key].append(entry)

    def get_prefix_length(self, network_ip: str, ip_to_check: str) -> int:
        for i, (a, b) in enumerate(zip(network_ip, ip_to_check)):
            if a != b:
                return i
        return len(network_ip)

    def find_longest_prefix_matches(self, ip_string: str):
        ip_to_check = IPAddress(ip_string)
        ip_to_check_binary = ip_to_check.to_binary()
        matches = []
        longest_prefix = -1
        debug_info = []

        for network, routes in self.routes.items():
            network_ip_binary = network.ip.to_binary()
            network_mask_binary = network.mask.to_binary()

            # Network Subnet Mask & Network IP --> R1
            r1 = ''.join([str(int(a) & int(b)) for a, b in zip(network_mask_binary, network_ip_binary)])

            # Count the number of ones in subnet mask
            number_of_ones_in_mask = network_mask_binary.count('1')

            # Network Block
            network_block = r1[:number_of_ones_in_mask]

            # Check if IP matches the network block
            if ip_to_check_binary.startswith(network_block):
                prefix_match = self.get_prefix_length(network_ip_binary, ip_to_check_binary)
                matches.append((network, prefix_match))
                longest_prefix = max(longest_prefix, prefix_match)

                debug_info.append({
                    "network": str(network),
                    "network_block": network_block,
                    "prefix_match": prefix_match
                })

        # Filter matches to only include those with the longest prefix
        longest_prefix_matches = [network for network, prefix in matches if prefix == longest_prefix]

        return longest_prefix_matches

    def find_best_route(self, ip_string: str) -> Optional[str]:
        longest_prefix_matches = self.find_longest_prefix_matches(ip_string)

        if not longest_prefix_matches:
            return None

        best_route = None
        best_route_score = (-float('inf'),) * 5  # Initialize with worst possible score

        for network in longest_prefix_matches:
            for route in self.routes[network]:
                current_score = (
                    route.local_pref,
                    route.self_origin,
                    -len(route.as_path),
                    {'IGP': 2, 'EGP': 1, 'UNK': 0}[route.origin],
                    -route.next_hop_ip.to_binary().count('1')
                )
                if current_score > best_route_score:
                    best_route_score = current_score
                    best_route = route

        return str(best_route.next_hop_ip) if best_route else None


    # def find_best_route(self, ip_string: str) -> str | None:
    #     """
    #     Finds the best route for the given IP address based on the longest prefix match.
    #
    #     Args:
    #         ip_string (str): The IP address to find the best route for.
    #
    #     Returns:
    #         Optional[IPAddress]: The next hop IP address if a route is found, otherwise None.
    #     """
    #     ip_to_check = IPAddress(ip_string)
    #     matching_routes = []
    #
    #     for network, route_entries in self.routes.items():
    #         match_length = self.get_prefix_length(network.ip, ip_to_check)
    #         if match_length > 0:
    #             for route in route_entries:
    #                 matching_routes.append((match_length, network, route))
    #
    #     if not matching_routes:
    #         return None
    #
    #     # Sort matching routes by prefix length (descending)
    #     matching_routes.sort(key=lambda x: x[0], reverse=True)
    #     max_prefix_length = matching_routes[0][0]
    #
    #     # Filter routes with the longest prefix match
    #     best_matches = [r for r in matching_routes if r[0] == max_prefix_length]
    #
    #     def tie_break_key(match):
    #         _, _, route = match
    #         return (
    #             route.local_pref,
    #             route.self_origin,
    #             -len(route.as_path),
    #             {'IGP': 2, 'EGP': 1, 'UNK': 0}[route.origin],
    #             -route.next_hop_ip.to_int()
    #         )
    #
    #     best_route = max(best_matches, key=tie_break_key)
    #     return str(best_route[2].next_hop_ip)

    def remove_route(self, network_str: str, subnet_mask: str, next_hop_ip: str) -> None:
        """
        Removes a route from the routing table.

        Args:
            :param network_str: The network address to remove.
            :param next_hop_ip:
            :param subnet_mask:
        """
        network_key = Network(network_str, subnet_mask)
        if network_key in self.routes:
            self.routes[network_key] = [route for route in self.routes[network_key]
                                        if str(route.next_hop_ip) != next_hop_ip]
            if not self.routes[network_key]:
                del self.routes[network_key]

    def update_route(self, network_str: str, subnet_mask: str, next_hop_ip: IPAddress,
                     **kwargs: Union[str, int, List[int]]) -> None:
        """
        Updates an existing route in the routing table with new values.
        """
        network_key = Network(network_str, subnet_mask)
        if network_key in self.routes:
            for route in self.routes[network_key]:
                if route.next_hop_ip == next_hop_ip:
                    for key, value in kwargs.items():
                        setattr(route, key, value)
                    break

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
        relations (Dict[str, str]): The relationship (customer, peer, etc.) with other routers.
        sockets (Dict[str, socket]): The sockets for communication with neighbors.
        ports (Dict[str, int]): The port numbers for each neighboring router.
        update_msgs (List[Dict]): A list of received update messages for the router.
        routing_table (RoutingTable): The router's routing table.
    """
    relations: Dict[str, str] = {}
    sockets: Dict[str, socket.socket] = {}
    ports: Dict[str, int] = {}
    update_msgs: List[Dict] = []

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
        self.update_msgs.append(parsed_msg)
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
        print(f"Routing Table before withdraw:\n{self.routing_table}")
        self.routing_table.remove_route(
            parsed_msg['msg'][0]['network'],
            parsed_msg['msg'][0]['netmask'],
            parsed_msg['src']
        )
        print(f"Routing Table after withdraw:\n{self.routing_table}")
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
        print(f"No route found for destination {parsed_msg['dst']}. Dropping packet.")

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
