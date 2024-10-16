class IPAddress:
    def __init__(self, ip_string):
        """
        Initialize the IPAddress object.

        Args:
            ip_string (str): A string representing an IPv4 address in dotted-decimal notation.
        """
        self.octets = list(map(int, ip_string.split('.')))

    def __str__(self):
        """
        Return a string representation of the IP address.

        Returns:
            str: The IP address in dotted-decimal notation.
        """
        return '.'.join(map(str, self.octets))

    def to_int(self):
        """
        Convert the IP address to an integer.

        Returns:
            int: The integer representation of the IP address.
        """
        return sum(octet << (24 - 8 * i) for i, octet in enumerate(self.octets))

    def to_binary(self):
        """
        Convert the IP address to a binary string.

        Returns:
            str: A 32-bit string of 0s and 1s representing the IPv4 address
        """
        return ''.join([format(octet, '08b') for octet in self.octets])

    @staticmethod
    def binary_to_ip_string(binary_string):
        """
        Convert a binary string to an IP address string

        Args:
            binary_string (str): A string of 0s and 1s representing an IP address

        Returns:
            str: A string representing the IP address in dotted-decimal notation.
        """
        # Ensure the binary string is 32 bits long
        binary_string = binary_string.zfill(32)

        # Convert each 8-bit chunk to an integer and then to a string
        octets = [str(int(binary_string[i:i + 8], 2)) for i in range(0, 32, 8)]

        # Join the octets with dots
        return '.'.join(octets)

    def octets_to_binary(self):
        """
        Convert the IP address's octets to a binary string.

        Returns:
            str: A 32-character string of 0s and 1s representing the IP address.
        """
        return ''.join([format(octet, '08b') for octet in self.octets])

    def __lt__(self, other):
        return self.to_int() < other.to_int()

    def __eq__(self, other):
        if isinstance(other, IPAddress):
            return self.octets == other.octets
        return False

    def __hash__(self):
        return hash(tuple(self.octets))

class Network:
    """
    A class to represent a network with an IP address and subnet mask.

    Attributes:
        ip (IPAddress): An IPAddress object representing the network address.
        mask (IPAddress): An IPAddress object representing the subnet mask.
    """
    def __init__(self, ip_string, mask_string):
        self.ip = IPAddress(ip_string)
        self.mask = IPAddress(mask_string)

    def __str__(self):
        return f"{self.ip}/{self.mask}"

    def __hash__(self):
        return hash((str(self.ip), str(self.mask)))

    def __eq__(self, other):
        return str(self.ip) == str(other.ip) and str(self.mask) == str(other.mask)

