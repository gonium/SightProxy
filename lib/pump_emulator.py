from packet_factory import *
from cryptograph import *

# from test_packets import *

# pump emulator

PUMP_RANDOM_DATA = None
PEER_RANDOM_DATA = None
PEER_PUBLIC_KEY = None
SECRET_KEY = None
INCOMING_KEY = None
OUTGOING_KEY = None


def generate_pump_response(data):
    # TODO replace with better storage
    global PUMP_RANDOM_DATA, PEER_RANDOM_DATA, PEER_RANDOM_DATA, SECRET_KEY, INCOMING_KEY, OUTGOING_KEY

    if (data == None):
        print "No data passed to generate_pump_response!"
        return

    reply = None
    r = parse_packet(data, key=INCOMING_KEY)

    if (r['status'] == 'identified'):
        print "Pump Emulator Processing: ", r['command']
        pretty(r['records'])
        print

        if (r['command'] == 'ConnectionRequest'):
            print "Replying with ConnectionResponse"
            reply = build_ConnectionResponse(comid=r['records']['ComID'])

        if (r['command'] == 'SynRequest'):
            print "Replying with SynAckResponse"
            reply = build_SynAckResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'])

        if (r['command'] == 'KeyRequest'):
            print "Replying with KeyResponse"
            PEER_PUBLIC_KEY = r['records']['PreMasterKey']
            PEER_RANDOM_DATA = r['records']['RandomData']
            (PUMP_RANDOM_DATA, SECRET_KEY) = createKeyData()
            reply = build_KeyResponse(comid=r['records']['ComID'],
                                      random_data=PUMP_RANDOM_DATA, secret_key=SECRET_KEY,
                                      peer_public_key=PEER_PUBLIC_KEY,
                                      lazy_timestamp=r['records']['TimeStamp'],
                                      nonce=r['records']['Nonce'])
            (OUTGOING_KEY, INCOMING_KEY) = deriveKeys(SECRET_KEY, KEY_SEED, PEER_RANDOM_DATA + PUMP_RANDOM_DATA)

        if (r['command'] == 'VerifyDisplayRequest'):
            print "Replying with VerifyDisplayResponse"
            reply = build_VerifyDisplayResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                key=OUTGOING_KEY)

        if (r['command'] == 'VerifyConfirmRequest'):
            print "Replying with VerifyConfirmResponse"
            reply = build_VerifyConfirmResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                key=OUTGOING_KEY)
    else:
        print r

    print
    print "PUMP EMULATOR REPLY"
    x = parse_packet(reply, key=OUTGOING_KEY)
    print x['status']
    if (x['status'] == "identified"):
        pretty(x['records'])
        print
    return reply


### self test

if __name__ == "__main__":
    print "Running pump emulator test parameters"
