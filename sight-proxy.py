import logging
import select
import time

from bluetooth import *

from lib.pump_emulator import *
from lib.client_emulator import *
from lib.keystore import *

EMULATE_PUMP = False
PARSE_WHEN_PROXY = False
CLIENT_CONNECT = False
MITM_PROXY = False
VERBOSE_LOGS = True

MAX_PACKET_COUNT = 1
ts = str(int(time.time()))
LOG_FILE = "logs/log-sight-proxy-" + ts + ".log"
APP_LOG_FILE = "logs/app-log-sight-proxy-" + ts + ".log"
if (not os.path.exists("logs")):
    os.mkdir("logs")

logging.basicConfig(filename=LOG_FILE, format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
logger = logging.getLogger('sight-proxy')
logger.setLevel(logging.DEBUG)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s : %(message)s')
console.setFormatter(formatter)
logger.addHandler(console)

handler = logging.FileHandler(APP_LOG_FILE)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
app_logger = logging.getLogger('sight-app-proxy')
app_logger.setLevel(logging.INFO)
app_logger.addHandler(handler)
app_logger.addHandler(console)

server_sock = BluetoothSocket(RFCOMM)
server_sock.bind(("", PORT_ANY))
server_sock.listen(1)

port = server_sock.getsockname()[1]

# serial_id_string = b'\x50\x55\x4d\x50\x2d\x4d\x44\x4c\x00\x00' # linux this doesn't work
serial_id_string = b'\x50\x55\x4d\x50\x2d\x4d\x44\x4c\x00'  # this string works on windows
search_serial_id_string = b'\x50\x55\x4d\x50\x2d\x4d\x44\x4c'  # note no 0x00 terminators

# raspberry pi jessie bluetooth has a PNP service by default
# advertise_service(pnp_sock, "PNP",
#                  service_classes=[PNP_INFO_CLASS],
#                  profiles=[PNP_INFO_PROFILE],
#                  protocols=[]
#                  )

advertise_service(server_sock, serial_id_string,
                  service_classes=[SERIAL_PORT_CLASS],
                  profiles=[SERIAL_PORT_PROFILE],
                  )

real_pump_mac = None
second_dongle_mac = None

fast_connect = True
SPACER = ' ' * 17

CLIENT_SOCK_PIPELINE = ['']
RSOCK_PIPELINE = ['']


def log_packet(packet, socket, direction, source):
    prefix = "????"

    if (direction == 'in' and source == 'real'):
        prefix = "<<<------ "
    if (direction == 'in' and source == 'emulated'):
        prefix = "<<<-----E "

    if (direction == 'out' and source == 'real'):
        prefix = "------>>> "
    if (direction == 'out' and source == 'emulated'):
        prefix = "E----->>> "
    if (direction == 'out' and source == 'proxy'):
        prefix = "P----->>> "

    hdr = hexdump.hexdump(packet, result="return")
    if (hdr != None and hdr != "None"):
        logger.debug("\n" + socket.upper() + " " + prefix + "\n" + hdr + "\n")


key_set('setting-RECONNECT', False)
key_set('setting-PUMP_APP_EMULATION', False)
key_set('setting-CLIENT_APP_EMULATION', False)

if (len(sys.argv) > 1):

    for a in range(1, len(sys.argv)):
        arg = sys.argv[a]
        print arg
        if arg == "--erase-keys":
            print SPACER + "Erasing keys for new pairing"
            key_erase_all()  # really needs some better state handling for key negotiation phase
            continue
        if arg == "--client-reconnect":
            print SPACER + "Using reconnect"
            RECONNECT = True
            key_set('setting-RECONNECT', True)
            continue
        if arg == "--emulate-client":
            print SPACER + "Emulating a client"
            CLIENT_CONNECT = True
            continue
        if arg == "--emulate-client-apps":
            print SPACER + "Emulating client app layer"
            CLIENT_APP_EMULATION = True
            key_set('setting-CLIENT_APP_EMULATION', True)
            continue
        if arg == "--mitm-proxy":
            print SPACER + "Running mitm proxy"
            MITM_PROXY = True
            CLIENT_CONNECT = True
            EMULATE_PUMP = True
            continue
        if arg == "--simple-proxy":
            print SPACER + "Running simple proxy"
            continue
        if arg == "--emulate-pump":
            print SPACER + "Emulating pump"
            EMULATE_PUMP = True
            continue
        if arg == "--emulate-pump-apps":
            print SPACER + "Emulating pump app layer"
            PUMP_APP_EMULATION = True
            key_set('setting-PUMP_APP_EMULATION', True)
            continue
        if arg == "--fast-connect":
            fast_connect = True
            continue
        if arg == "--slow-connect":
            fast_connect = False
            continue

        if (real_pump_mac == None):
            real_pump_mac = arg
            if (real_pump_mac == 'emulate'):
                print SPACER + "Using pump emulator!"
                EMULATE_PUMP = True
            else:
                print SPACER + "Real pump is at:", real_pump_mac
        else:
            second_dongle_mac = arg
            print "Outbound connections will go via:", second_dongle_mac

print SPACER + "Fast connect is set to:", fast_connect

init_client_emulator()
init_pump_emulator()

print

if (CLIENT_CONNECT and not real_pump_mac):
    raise ValueError("Client connect set but no mac address specified")

PERSIST_CLIENT_CONNECTION = True  # whether to shut it down or not

rsock = None

while True:
    print "Waiting on channel %d" % port

    mapping = {}
    input_list = []

    client_sock = None

    if not CLIENT_CONNECT or MITM_PROXY:
        client_sock, client_info = server_sock.accept()
        logger.info("Accepted connection from " + str(client_info))
        input_list.append(client_sock)
        # client_sock.setblocking(0)
    else:
        delay = 8
        logger.info("Delaying client startup by " + str(delay) + " seconds to allow things to settle")
        time.sleep(delay)

    if ((not EMULATE_PUMP and real_pump_mac != None) or MITM_PROXY):
        logger.info("Searching real device: " + real_pump_mac)

        if (not fast_connect):
            while True:
                service_matches = find_service(name=search_serial_id_string, address=real_pump_mac)

                if len(service_matches) == 0:
                    logger.error("Couldn't find the pump service on: " + real_pump_mac)
                    time.sleep(1)
                else:
                    logger.info("Found real pump service!")
                    break

            first_match = service_matches[0]
            port = first_match["port"]
            name = first_match["name"]
            host = first_match["host"]

        else:
            print "Using fast connect.."
            port = 1
            name = search_serial_id_string
            host = real_pump_mac

        backoff = 0.1
        while True:
            try:
                logger.info("Connecting to real \"%s\" on %s (%s)" % (name, host, port))
                if (rsock == None):
                    rsock = BluetoothSocket(RFCOMM)
                    if (second_dongle_mac != None):
                        rsock.bind((second_dongle_mac, 0))

                # if (rsock.connected == False):
                # TODO check connected??
                rsock.connect((host, port))
                #    logger.info("Connected to real")
                # else:
                #    logger.info("Already connected to real")

                break
            except BluetoothError, e:
                logger.error("Connect error: " + str(e))
                if (str(e) == "(77, 'File descriptor in bad state')"):
                    print "Got problem with socket - exit for now"
                    sys.exit(5)

                time.sleep(backoff)
                backoff = backoff + 0.2

        if not client_sock is None:
            mapping[client_sock] = rsock
            mapping[rsock] = client_sock

        input_list.append(rsock)

    buffer_size = 1024

    if CLIENT_CONNECT:
        print "Sending initial client data!"
        rsock.send(generate_client_response("initial", logger=logger, VERBOSE_LOGS=VERBOSE_LOGS))

    print "Waiting for incoming data"

    try:
        while True:

            selector = select.select
            inputready, outputready, exceptready = selector(input_list, [], [])
            for active_socket in inputready:

                data = active_socket.recv(buffer_size)

                if len(data) == 0:
                    break
                else:

                    log_packet(packet=data, socket="in" if active_socket == client_sock else "out", direction="in",
                               source="real")

                    which_pipeline = CLIENT_SOCK_PIPELINE if active_socket is client_sock else RSOCK_PIPELINE
                    packet_pipeline = []

                    pdata = getPipelinedPacket(data, pipeline=which_pipeline)
                    if (not pdata is None):
                        packet_pipeline += [pdata]

                    pdata = getPipelinedPacket('', pipeline=which_pipeline)
                    while not pdata is None:
                        packet_pipeline += [pdata]
                        pdata = getPipelinedPacket('', pipeline=which_pipeline)

                    for data in packet_pipeline:
                        client_reply = None
                        proxied_packet = False

                        if MITM_PROXY:
                            if (active_socket is client_sock):
                                which_in_key = key_get('real_client_incoming')
                                which_out_key = key_get('real_pump_outgoing')
                                which_log_socket = "OUT"  # opposite
                                channel = 'out'
                                loghelper = 'FROM HAND '
                            else:
                                which_in_key = key_get('real_pump_incoming')
                                which_out_key = key_get('real_client_outgoing')
                                which_log_socket = "IN"  # opposite
                                channel = 'in'
                                loghelper = 'FROM PUMP '

                            p = parse_packet(data, key=which_in_key, logger=logger, loghelper=loghelper,
                                             app_logger=app_logger)
                            r = p['records']
                            if p['command'] == 'Data' and 'Decrypted' in r and r['Decrypted'] and p['valid'] == True:
                                print "Create packet again!!!!!"
                                new_packet = reEncryptBlock(nonce=r['Nonce'], payload=r['Decrypted'], key=which_out_key,
                                                            packet=data, channel=channel)
                                if (new_packet != None):
                                    proxied_packet = True
                                    if (mapping.has_key(active_socket)):
                                        # probably not needed on all platforms
                                        outputs = list(splitByMTU(new_packet, 96))
                                        for item in outputs:
                                            mapping[active_socket].send(item)  # !!
                                            hexdump.hexdump(item)

                                        log_packet(packet=new_packet, socket=which_log_socket, direction='out',
                                                   source="proxy")
                                else:
                                    logger.critical("Cannot re-encrypt packet!")

                        if not EMULATE_PUMP or MITM_PROXY:
                            if not CLIENT_CONNECT:
                                if (mapping.has_key(active_socket)):
                                    mapping[active_socket].send(data)
                                    if PARSE_WHEN_PROXY:
                                        if (active_socket is client_sock):
                                            pretty_parsed(
                                                parse_packet(data, key_get('known_incoming_key'), logger=logger))
                                        else:
                                            pretty_parsed(
                                                parse_packet(data, key_get('known_outgoing_key'), logger=logger))
                            elif (active_socket is rsock) and proxied_packet == False:
                                client_reply = generate_client_response(data, logger=logger, VERBOSE_LOGS=VERBOSE_LOGS)
                                if not client_reply is None:
                                    active_socket.send(client_reply)
                                    log_packet(packet=client_reply,
                                               socket="in" if active_socket == client_sock else "out",
                                               direction="out", source="emulated")

                                else:
                                    logger.info("No client response generated for packet")

                        if EMULATE_PUMP and (active_socket is client_sock) and proxied_packet == False:
                            pump_response = generate_pump_response(data, logger=logger, VERBOSE_LOGS=VERBOSE_LOGS)
                            if not pump_response == None:
                                # do we actually need to split?
                                outputs = list(splitByMTU(pump_response, 110))
                                for item in outputs:
                                    active_socket.send(item)
                                log_packet(packet=pump_response,
                                           socket="in" if active_socket == client_sock else "out",
                                           direction="out", source="emulated")

    except IOError:
        pass

    logger.info("socket disconnect")

    if (boolean_get('setting-RECONNECT')):
        logger.info("exit due to reconnect")
        sys.exit(0)

    if (rsock != None) and (PERSIST_CLIENT_CONNECTION == False):
        rsock.close()
        rsock = None
    if (client_sock != None):
        client_sock.close()

server_sock.close()
logger.info("exit")
