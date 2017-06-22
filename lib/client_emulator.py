from keystore import *
from packet_factory import *
from cryptograph import *
from test_packets import *

# client device emulator

REAL_PUMP_RANDOM_DATA = None
OUR_RANDOM_DATA = None
PEER_PUBLIC_KEY = None
SECRET_KEY = None
CLIENT_EMU_INCOMING_KEY = None
CLIENT_EMU_OUTGOING_KEY = None
COMID = None


def generate_client_response(data, logger=None, VERBOSE_LOGS=True):
    # TODO replace with better storage
    global REAL_PUMP_RANDOM_DATA, OUR_RANDOM_DATA, PEER_RANDOM_DATA, RECEIVED_SECRET_KEY, CLIENT_EMU_INCOMING_KEY, CLIENT_EMU_OUTGOING_KEY, COMID

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
        print "generate client response parse packet"
        r = parse_packet(data, key=CLIENT_EMU_INCOMING_KEY)

        if (r['status'] == 'identified'):

            log_string = "Client Emulator Processing: " + r['command'] + "\n"
            log_string += pretty_parsed_string(r) + "\n"

            if (VERBOSE_LOGS == True):
                logger.info("\n" + log_string)
            else:
                print log_string

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
                REAL_PUMP_RANDOM_DATA = r['records']['RandomData']
                RECEIVED_SECRET_KEY = decryptWithOurRSAkey(r['records']['PreMasterKey'])
                (CLIENT_EMU_INCOMING_KEY, CLIENT_EMU_OUTGOING_KEY) = deriveKeys(RECEIVED_SECRET_KEY, KEY_SEED,
                                                                                OUR_RANDOM_DATA + REAL_PUMP_RANDOM_DATA)
                key_set('real_pump_incoming', CLIENT_EMU_INCOMING_KEY)
                key_set('real_pump_outgoing', CLIENT_EMU_OUTGOING_KEY)

                logger.info("CLIENT OUTGOING_KEY: " + hd(CLIENT_EMU_OUTGOING_KEY))
                logger.info("CLIENT INCOMING_KEY: " + hd(CLIENT_EMU_INCOMING_KEY))

                print "Replying with VerifyDisplayRequest"
                reply = build_VerifyDisplayRequest(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                   key=CLIENT_EMU_OUTGOING_KEY)

            if (r['command'] == 'VerifyDisplayResponse'):
                print "Replying with VerifyConfirmRequest"
                reply = build_VerifyConfirmRequest(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                   key=CLIENT_EMU_OUTGOING_KEY)



        else:
            print r

    x = parse_packet(reply, key=CLIENT_EMU_OUTGOING_KEY)

    log_string = "\nCLIENT EMULATOR REPLY\n" + x['status'] + "\n" + pretty_parsed_string(x) + "\n"

    if (VERBOSE_LOGS == True):
        logger.info("\n" + log_string)
    else:
        print log_string

    return reply


### self test

if __name__ == "__main__":
    print "Running client emulator test parameters"
    parse_packet(generate_client_response(TESTPACKET0A))
