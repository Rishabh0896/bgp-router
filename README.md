# BGP Router
Teammates : Rishabh Gupta and Thuy Trang Ngo

# Introduction
This document outlines the design and implementation strategy for a router that supports functionalities for BGP, 
including path selection, forwarding, and maintaining routing tables.

# Implementation
## IP Address
A large part of this project resolves around working with IPv4 addresses and parsing the address into network and host portion. To easy work with the addresses, we implement IP Address class and Network class. 
### IPAddress Class
Represents IPv4 addresses with methods for:
* Conversion between IP string octets, integer, and binary representations
* Method for comparison

## Network Class
Store an IP and the subnet mask as attributes. 

## Routing Table
Represents the routing table of one BGP router. This router is receiving messages from other routers, and 
store information from those messages as entries in the routing table. After updating the routing table, it then advertises its route to the appropriate peers. 

### Route Entry
The RouteEntry class represents a routing table entry, containing essential information about the route to a network.
It has these attributes:
- next_hop_ip (IPAddress): IP address of the next hop router
- local_pref (int): Local preference value for the route
- as_path (List[int]): List of Autonomous System numbers in the path
- origin (str): Origin type of the route (e.g., IGP, EGP)
- self_origin (bool): Indicates if the route originated from this router

Two entries are considered equal if all their attributes match:
- Same AS path
- Identical next hop IP
- Equal local preference
- Matching origin type
- Identical self-origin status

### Operation
## Routing Table Operations
We implement multiple operation for these routing tables:
1. **Adding Routes**: 
   - Adds new route entry to the table, using Network object as the key and RoutingEntry object as value.
   - Automatically triggers network aggregation after each addition.
   - Advertise updates/withdraws to neighboring routers.

2. **Route Removal**:
   - Receive route withdrawal message and remove corresponding RouteEntry in table.
   - If route has been aggregated, empty table and rebuild table without the route in withdrawal message. 
   - Advertise updates/withdraws to neighboring routers.

3. **Best Route Selection**:
   - Implements the BGP decision process to select the best route for a given source and destination.
   - Considers factors like longest common prefix, local preference, AS path length, origin, and next hop IP.
   
4. **Network Aggregation**:
   - Determine if two network can be aggregated based on RouteEntry class. 
   - Aggregate and replace previous RouteEntries with a new RouteEntry.

5. **Longest Prefix Matching**:
   - `find_longest_prefix_matches()` identifies networks matching a given IP, and pick the one with longest matching prefix.

6. **Table Representation**:
   - `__str__()` provides a formatted string representation of the routing table.
   - `dump_table()` creates a serializable representation of the table.

### Challenges
One challenge we run into was figuring out how to convert the logic from lectures to actual code representation when dealing with IP, especially the binary operations.
By running through the examples in the config, we were able to run through basic test cases and break it into code for representation.

Another challenge is organizing the code, since there are many complex operations. We organized everything base on class, class-based method, and static method to achieve good separation of responsibility and encapsulate attributes and useful methods. 

### Testing
We used the test described in config to test the correctness of our code. The test helps to identify gaps in our code's logic and shows the appropriate behavior for all functions. 

