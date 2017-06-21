from packet_factory import *
from cryptograph import *

from test_packets import *

# client device emulator

PUMP_RANDOM_DATA = None
OUR_RANDOM_DATA = None
PEER_PUBLIC_KEY = None
SECRET_KEY = None
INCOMING_KEY = None
OUTGOING_KEY = None
COMID = None


def generate_client_response(data, logger=None):
    # TODO replace with better storage
    global PUMP_RANDOM_DATA, OUR_RANDOM_DATA, PEER_RANDOM_DATA, SECRET_KEY, INCOMING_KEY, OUTGOING_KEY, COMID

    if (COMID == None):
        # COMID = int(hd(getRandomBytes(2)[::-1]), 16) & 0xfff
        COMID = 1

    if (OUR_RANDOM_DATA == None):
        OUR_RANDOM_DATA = getRandomBytes(28)
        print "Setting our random data to: " + hd(OUR_RANDOM_DATA)

    if (data == None):
        print "No data passed to generate_client_response!"
        return

    reply = None

    if (data == "initial"):
        print "Client emulator initial ConnectionRequest"
        reply = build_ConnectionRequest()

    else:
        r = parse_packet(data, key=INCOMING_KEY)

        if (r['status'] == 'identified'):
            print "Client Emulator Processing: ", r['command']
            print
            # pretty(r['records'])
            pretty_parsed(r)
            print

            if ('valid' in r and r['valid'] == False):
                logger.critical("Trailer CCM INVALID! - skipping")
                return None

            if (r['command'] == 'ConnectionResponse'):
                print "Replying with KeyRequest"
                reply = build_KeyRequest(comid=COMID,
                                         random_data=OUR_RANDOM_DATA,
                                         our_public_key=publicKeyToString(getRSAkey()),
                                         lazy_timestamp=getCurrentTimeStamp()
                                         )

            if (r['command'] == 'KeyResponse'):
                # get keys
                PUMP_RANDOM_DATA = r['records']['RandomData']
                SECRET_KEY = decryptWithOurRSAkey(r['records']['PreMasterKey'])
                (INCOMING_KEY, OUTGOING_KEY) = deriveKeys(SECRET_KEY, KEY_SEED, OUR_RANDOM_DATA + PUMP_RANDOM_DATA)
                logger.info("CLIENT OUTGOING_KEY: " + hd(OUTGOING_KEY))
                logger.info("CLIENT INCOMING_KEY: " + hd(INCOMING_KEY))

                print "Replying with VerifyDisplayRequest"
                reply = build_VerifyDisplayRequest(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                   key=OUTGOING_KEY)

            if (r['command'] == 'VerifyDisplayResponse'):
                print "Replying with VerifyConfirmRequest"
                reply = build_VerifyConfirmRequest(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                   key=OUTGOING_KEY)



        else:
            print r

    print
    print "CLIENT EMULATOR REPLY"
    x = parse_packet(reply, key=OUTGOING_KEY)
    print x['status']
    pretty_parsed(x)
    return reply


### self test

if __name__ == "__main__":
    print "Running client emulator test parameters"
    parse_packet(generate_client_response(TESTPACKET0A))
