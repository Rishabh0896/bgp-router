import json

if __name__ == '__main__':
    msg = {"type": "table", "src": "192.168.0.2", "dst": "192.168.0.1", "msg": [{"network": "192.168.0.0", "netmask": "255.255.255.0", "peer": "192.168.0.2", "localpref": 100, "ASPath": [1], "selfOrigin": True, "origin": "EGP"}, {"network": "172.168.0.0", "netmask": "255.255.0.0", "peer": "172.168.0.2", "localpref": 100, "ASPath": [2], "selfOrigin": True, "origin": "EGP"}]}
    msg = json.dumps(msg)
    msg = msg.encode('utf-8')
    print(msg)