class IPAddress:
    def __init__(self, ip_string):
        self.octets = list(map(int, ip_string.split('.')))

    def __str__(self):
        return '.'.join(map(str, self.octets))

    def to_int(self):
        return sum(octet << (24 - 8 * i) for i, octet in enumerate(self.octets))

    def __lt__(self, other):
        return self.to_int() < other.to_int()


class Network:
    def __init__(self, ip_string, mask_string):
        self.ip = IPAddress(ip_string)
        self.mask = IPAddress(mask_string)

    def __str__(self):
        return f"{self.ip}/{self.mask}"

    def __hash__(self):
        return hash((str(self.ip), str(self.mask)))

    def __eq__(self, other):
        return str(self.ip) == str(other.ip) and str(self.mask) == str(other.mask)
