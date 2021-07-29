import logging

# Suppress warnings at import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Import scapy
try:
    from scapy.all import *
    from scapy.layers.inet6 import *
except ImportError as e:
    raise ImportError('\nCould not import Scapy. \nPlease install it and try again ("pip3 install scapy").\n')

# turn off verbosity
conf.verb = 0

# ----global variables---#
destip = ""


# prints program usage on screen
def usage():
    print('Usage : <script_name> <ipv6_address>')
    print('Where :')
    print('\tip_address : Destination IPv6 address')


def checking(da):
    request = IPv6(dst=da) / ICMPv6HAADRequest(id=42)
    try:
        responses, unanswered = sr(request, timeout=2, retry=3)

        for s, r in responses:
            if r[0].haslayer(ICMPv6HAADRequest) and r[0].src == da:
                # r[0].show()
                return True

    except socket.error as e:
        (error, string) = e
        if error == 19:
            print('Error: Invalid Interface %s provided. Exiting...' % (interface))
            sys.exit()
        else:
            print('Socket error: %s' % (e))
            sys.exit()
    except Exception as e:
        print('Some Exception occured: %s' % (e))
        sys.exit()


def main():
    # check for arguments
    if len(sys.argv) != 2:
        usage()
        sys.exit()

    destip = sys.argv[1]

    if checking(destip):
        print("true")
        sys.exit()
    print("false")


if __name__ == "__main__":
    main()
