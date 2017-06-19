import logging
import select
import time

from bluetooth import *

from lib.pump_emulator import *

# pnp_sock = BluetoothSocket(RFCOMM)
# pnp_sock.bind(("", 5))
# pnp_sock.listen(1)

EMULATE_PUMP = False

LOG_FILE = "logs/log-sight-proxy-" + str(int(time.time())) + ".log"
if (not os.path.exists("logs")):
    os.mkdir("logs")

logging.basicConfig(filename=LOG_FILE, format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
logger = logging.getLogger('sight-proxy')
logger.setLevel(logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s : %(message)s')
console.setFormatter(formatter)
logger.addHandler(console)

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

fast_connect = True

if (len(sys.argv) > 1):
    real_pump_mac = sys.argv[1]
    if (real_pump_mac == 'emulate'):
        print "                 Using pump emulator!"
        EMULATE_PUMP = True
    else:
        print "                 Real pump is at:", real_pump_mac

if (len(sys.argv) > 2):
    second_dongle_mac = sys.argv[2]
    print "Outbound connections will go via:", second_dongle_mac
else:
    second_dongle_mac = None

if (len(sys.argv) > 3):
    if (sys.argv[3] == "fast"):
        fast_connect = True
    else:
        fast_connect = False

print "          Fast connect is set to:", fast_connect

print

while True:
    print "Waiting on channel %d" % port

    mapping = {}
    input_list = []
    rsock = None

    client_sock, client_info = server_sock.accept()
    logger.info("Accepted connection from " + str(client_info))
    input_list.append(client_sock)
    # client_sock.setblocking(0)

    if (not EMULATE_PUMP and real_pump_mac != None):
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
                rsock = BluetoothSocket(RFCOMM)
                if (second_dongle_mac != None):
                    rsock.bind((second_dongle_mac, 0))
                rsock.connect((host, port))
                logger.info("Connected to real")
                break
            except BluetoothError, e:
                logger.error("Connect error: " + str(e))
                time.sleep(backoff)
                backoff = backoff + 0.2

        mapping[client_sock] = rsock
        mapping[rsock] = client_sock

        input_list.append(rsock)

    buffer_size = 1024

    print "Waiting for incoming data"

    try:
        while True:

            selector = select.select
            inputready, outputready, exceptready = selector(input_list, [], [])
            for active_socket in inputready:

                data = active_socket.recv(buffer_size)
                # TODO needs chunking pipeline
                if len(data) == 0:
                    break
                else:

                    packet_pipeline = []

                    pdata = getPipelinedPacket(data)
                    if (not pdata is None):
                        packet_pipeline += [ pdata ]

                    pdata = getPipelinedPacket('')
                    while not pdata is None:
                        packet_pipeline += [ pdata ]
                        pdata = getPipelinedPacket('')

                    for data in packet_pipeline:
                        if not EMULATE_PUMP:
                            if (mapping.has_key(active_socket)):
                                mapping[active_socket].send(data)

                        if (active_socket is client_sock):
                            prefix = "------>>> "
                        else:
                            prefix = "<<<------ "
                        if (data != None):
                            hdr = hexdump.hexdump(data, result="return")
                            if (hdr != None and hdr != "None"):
                                logger.info("\n" + prefix + "\n" + hdr + "\n")

                        if EMULATE_PUMP:
                            pump_response = generate_pump_response(data)
                            if not pump_response == None:
                                active_socket.send(pump_response)
                                prefix = "<<<-----E "
                                hdr = hexdump.hexdump(pump_response, result="return")
                                if (hdr != None and hdr != "None"):
                                    logger.info("\n" + prefix + "\n" + hdr + "\n")


    except IOError:
        pass

    logger.info("socket disconnect")
    if (rsock != None):
        rsock.close()
    client_sock.close()

server_sock.close()
logger.info("exit")
