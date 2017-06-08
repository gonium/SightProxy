from bluetooth import *
import hexdump

# pnp_sock = BluetoothSocket(RFCOMM)
# pnp_sock.bind(("", 5))
# pnp_sock.listen(1)

server_sock = BluetoothSocket(RFCOMM)
server_sock.bind(("", PORT_ANY))
server_sock.listen(1)

port = server_sock.getsockname()[1]

# serial_id_string = b'\x50\x55\x4d\x50\x2d\x4d\x44\x4c\x00\x00' # linux this doesn't work
serial_id_string = b'\x50\x55\x4d\x50\x2d\x4d\x44\x4c\x00'  # this string works on windows

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

while True:
    print("Waiting on channel %d" % port)

    client_sock, client_info = server_sock.accept()
    print("Accepted connection from ", client_info)

    # TODO add outbound proxy and two-way data relaying

    try:
        while True:
            data = client_sock.recv(1024)
            if len(data) == 0: break
            # print("received [%s]" % data)
            print "-> "
            print hexdump.hexdump(data)
    except IOError:
        pass

    print("socket disconnect")

    client_sock.close()

server_sock.close()
print("exit")
