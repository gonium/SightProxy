from keystore import *
from packet_factory import *
from cryptograph import *

# from test_packets import *

# pump emulator

PUMP_RANDOM_DATA = None
PEER_RANDOM_DATA = None
PEER_PUBLIC_KEY = None
SECRET_KEY = None
PUMP_EMU_INCOMING_KEY = None
PUMP_EMU_OUTGOING_KEY = None


def generate_pump_response(data, logger=None, VERBOSE_LOGS=True):
    # TODO replace with better storage
    global PUMP_RANDOM_DATA, PEER_RANDOM_DATA, PEER_RANDOM_DATA, SECRET_KEY, PUMP_EMU_INCOMING_KEY, PUMP_EMU_OUTGOING_KEY

    if (data == None):
        print "No data passed to generate_pump_response!"
        return

    reply = None
    r = parse_packet(data, key=PUMP_EMU_INCOMING_KEY, logger=logger)

    if (r['status'] == 'identified'):
        log_string = "Pump Emulator Processing: " + r['command'] + "\n"
        log_string += pretty_parsed_string(r) + "\n"

        if (VERBOSE_LOGS == True):
            logger.info("\n" + log_string)
        else:
            print log_string

        if ('valid' in r and r['valid'] == False):
            logger.critical("Trailer CCM INVALID! - skipping")
            return None

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
            (PUMP_EMU_OUTGOING_KEY, PUMP_EMU_INCOMING_KEY) = deriveKeys(SECRET_KEY, KEY_SEED,
                                                                        PEER_RANDOM_DATA + PUMP_RANDOM_DATA)
            key_set('real_client_incoming', PUMP_EMU_INCOMING_KEY)
            key_set('real_client_outgoing', PUMP_EMU_OUTGOING_KEY)
            logger.info("PUMPEMU OUTGOING_KEY: " + hd(PUMP_EMU_OUTGOING_KEY))
            logger.info("PUMPEMU INCOMING_KEY: " + hd(PUMP_EMU_INCOMING_KEY))

        if (r['command'] == 'VerifyDisplayRequest'):
            print "Replying with VerifyDisplayResponse"
            reply = build_VerifyDisplayResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                key=PUMP_EMU_OUTGOING_KEY)

        if (r['command'] == 'VerifyConfirmRequest'):
            print "Replying with VerifyConfirmResponse"
            reply = build_VerifyConfirmResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                key=PUMP_EMU_OUTGOING_KEY)
    else:
        print r

    x = parse_packet(reply, key=PUMP_EMU_OUTGOING_KEY)
    log_string = "\nPUMP EMULATOR REPLY\n" + x['status'] + "\n" + pretty_parsed_string(x) + "\n"

    # print x['status']
    # pretty_parsed(x)
    # if (x['status'] == "identified"):
    #     pretty(x['records'])
    # print

    if (VERBOSE_LOGS == True):
        logger.info("\n" + log_string)
    else:
        print log_string

    return reply


### self test

if __name__ == "__main__":
    print "Running pump emulator test parameters"
