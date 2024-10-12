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

    def add_route(self, network: str, subnet_mask: str, next_hop_ip: IPAddress, local_pref: int,
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

    @staticmethod
    def longest_prefix_match(network_ip: IPAddress, ip_to_check: IPAddress, subnet_mask: IPAddress) -> int:
        """
        Finds the length of the longest matching prefix between two IP addresses based on the subnet mask.

        Args:
            network_ip (IPAddress): The network IP address.
            ip_to_check (IPAddress): The IP address to check for matching.
            subnet_mask (IPAddress): The subnet mask.

        Returns:
            int: The length of the longest matching prefix.
        """
        longest_prefix = 0
        for net_octet, check_octet, mask_octet in zip(network_ip.octets, ip_to_check.octets, subnet_mask.octets):
            for bit in range(7, -1, -1):
                mask_bit = (mask_octet >> bit) & 1
                if mask_bit == 0:
                    return longest_prefix

                net_bit = (net_octet >> bit) & 1
                check_bit = (check_octet >> bit) & 1

                if net_bit == check_bit:
                    longest_prefix += 1
                else:
                    return longest_prefix
        return longest_prefix

    def find_best_route(self, ip_string: str) -> str | None:
        """
        Finds the best route for the given IP address based on the longest prefix match.

        Args:
            ip_string (str): The IP address to find the best route for.

        Returns:
            Optional[IPAddress]: The next hop IP address if a route is found, otherwise None.
        """
        ip_to_check = IPAddress(ip_string)
        matching_routes = []

        for network, route_entries in self.routes.items():
            match_length = self.longest_prefix_match(network.ip, ip_to_check, network.mask)
            if match_length > 0:
                for route in route_entries:
                    matching_routes.append((match_length, network, route))

        if not matching_routes:
            return None

        # Sort matching routes by prefix length (descending)
        matching_routes.sort(key=lambda x: x[0], reverse=True)
        max_prefix_length = matching_routes[0][0]

        # Filter routes with the longest prefix match
        best_matches = [r for r in matching_routes if r[0] == max_prefix_length]

        def tie_break_key(match):
            _, _, route = match
            return (
                route.local_pref,
                route.self_origin,
                -len(route.as_path),
                {'IGP': 2, 'EGP': 1, 'UNK': 0}[route.origin],
                -route.next_hop_ip.to_int()
            )

        best_route = max(best_matches, key=tie_break_key)
        return str(best_route[2].next_hop_ip)

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

    def advertise_update(self, msg: Dict, receive_network: str) -> None:
        """
        Advertises a network path to all neighbors except the one from which the message was received.

        Args:
            msg (Dict): The message containing network path information.
            receive_network (str): The network from which the message was received.
        """
        for network in self.sockets:
            if network != receive_network:
                # Form a new update message here
                update_msg = {"type": "update", "src": self.our_addr(network), "dst": network, "msg": {
                    "network": msg["network"],
                    "netmask": msg["netmask"],
                    "ASPath": [self.asn] + msg["ASPath"],
                }}
                self.sockets[network].sendto(json.dumps(update_msg).encode('utf-8'), ('localhost', self.ports[network]))

    def advertise_withdraw(self, msg: Dict, receive_network: str) -> None:
        for network in self.sockets:
            if network != receive_network:
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

        if next_hop_ip:
            self.send(next_hop_ip, json.dumps(parsed_msg))
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
            "src": self.our_addr(parsed_msg['network']),
            "dst": parsed_msg['src'],
            "type": "no route",
            "msg": parsed_msg['msg'],
        }
        self.send(parsed_msg['network'], json.dumps(no_route_message))
        print(f"No route found for destination {parsed_msg['dst']}. Dropping packet.")
