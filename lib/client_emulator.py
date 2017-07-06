from app_factory import *
from dirtyemulator import *
from enchiridion import *

# client device emulator

REAL_PUMP_RANDOM_DATA = None
OUR_RANDOM_DATA = None
PEER_PUBLIC_KEY = None
SECRET_KEY = None
CLIENT_EMU_INCOMING_KEY = None
CLIENT_EMU_OUTGOING_KEY = None
COMID = None

PAIRING_PENDING_RETRY = 0

CLIENT_APP_EMULATION = False
CLIENT_STEP = 0

RESEARCH_CLIENT = False
RECONNECT = False


def init_client_emulator():
    global RECONNECT, CLIENT_APP_EMULATION, RESEARCH_CLIENT, DIRTY_CLIENT_SCRIPT, DIRTY_CLIENT

    RECONNECT = boolean_get('setting-RECONNECT')
    CLIENT_APP_EMULATION = boolean_get('setting-CLIENT_APP_EMULATION')
    if (RECONNECT == True):
        print "RECONNECT MODE"
        if RESEARCH_CLIENT == True:
            DIRTY_CLIENT_SCRIPT = DIRTY_CLIENT_RESEARCH
        else:
            DIRTY_CLIENT_SCRIPT = DIRTY_CLIENT_RECONNECT
    else:
        DIRTY_CLIENT_SCRIPT = DIRTY_CLIENT


def generate_client_response(data, logger=None, VERBOSE_LOGS=True):
    global PAIRING_PENDING_RETRY
    global HIGHEST_NONCE
    global CLIENT_STEP, CLIENT_APP_EMULATION
    global REAL_PUMP_RANDOM_DATA, OUR_RANDOM_DATA, PEER_RANDOM_DATA, RECEIVED_SECRET_KEY, CLIENT_EMU_INCOMING_KEY, CLIENT_EMU_OUTGOING_KEY, COMID

    if (COMID == None):
        COMID = 1

    if (OUR_RANDOM_DATA == None):
        OUR_RANDOM_DATA = getRandomBytes(28)
        print "Setting our random data to: " + hd(OUR_RANDOM_DATA)

    if (data == None):
        print "No data passed to generate_client_response!"
        return

    reply = None

    if (data == "initial"):

        HIGHEST_NONCE['in'] = 0
        if (RECONNECT == True):
            print "Client emulator initial SynRequest"

            HIGHEST_NONCE['out'] = 0 if key_get('HIGHEST_NONCE-out') == None else key_get(
                'HIGHEST_NONCE-out')
            HIGHEST_NONCE['out'] += 200000
            key_set('HIGHEST_NONCE-out', HIGHEST_NONCE['out'])
            CLIENT_EMU_INCOMING_KEY = key_get('real_pump_incoming')
            CLIENT_EMU_OUTGOING_KEY = key_get('real_pump_outgoing')
            COMID = key_get('out-comid')

            if RESEARCH_CLIENT == True:
                r = {'records': {}}
                r['records']['ComID'] = COMID
                r['records']['Nonce'] = HIGHEST_NONCE['out']

                reply = clientGetDirtyReply(r)
            else:
                reply = build_SynRequest(comid=COMID, nonce=longToBytes(HIGHEST_NONCE['out'], 13),
                                         key=CLIENT_EMU_OUTGOING_KEY, channel='out')
        else:
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
                                                   key=CLIENT_EMU_OUTGOING_KEY, channel='out')
            if (r['command'] == 'SynAckResponse'):
                print "Received SynAck - using dirty emulator"
                reply = clientGetDirtyReply(r)

            if (r['command'] == 'VerifyDisplayResponse'):
                print "Replying with VerifyConfirmRequest"
                reply = build_VerifyConfirmRequest(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                   key=CLIENT_EMU_OUTGOING_KEY, channel='out')
                key_set("out-comid", r['records']['ComID'])

            if (r['command'] == 'VerifyConfirmResponse'):
                if (r['records']['Decrypted'] == '\x93\x06'):
                    PAIRING_PENDING_RETRY += 1
                    if (PAIRING_PENDING_RETRY < 20):
                        logger.info("Pairing pending - wait 2 seconds and retry")
                        time.sleep(2)
                        reply = build_VerifyConfirmRequest(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                           key=CLIENT_EMU_OUTGOING_KEY, channel='out')
                elif (r['records']['Decrypted'] == '\x3b\x2e'):
                    logger.info("Pairing confirmed!")
                    key_set("out-comid", r['records']['ComID'])
                    PAIRING_PENDING_RETRY = 0
                    reply = clientGetDirtyReply(r)

                else:
                    logger.critical("Pairing REJECTED!!!!!!!!")
                    PAIRING_PENDING_RETRY = 0

            if CLIENT_APP_EMULATION:
                if (r['command'] == 'Data'):
                    print "Attempting to process data packet"

                    reply = clientGetDirtyReply(r)

                    if (reply == None):
                        # receiving a challenge
                        if (r['records']['Decrypted'].startswith("\x20\x00\xD2\xF3\x00\x00")):
                            challenge_bytes = r['records']['Decrypted'][6:]
                            print "Received challenge! " + hd(challenge_bytes)

                            service_to_activate = key_get('last-requested-challenge-service')
                            service_version = key_get('last-requested-challenge-version')

                            challenge_response = enc_getchallenge_response(service_to_activate, challenge_bytes)

                            # send challenge response
                            if (challenge_response != None):
                                reply = build_AppServiceChallengeResponse(nonce=r['records']['Nonce'], channel='out',
                                                                          comid=r['records']['ComID'],
                                                                          key=CLIENT_EMU_OUTGOING_KEY,
                                                                          service_to_activate=service_to_activate,
                                                                          service_version=service_version,
                                                                          challenge_response=challenge_response)
                            else:
                                logger.critical(
                                    "Could not gain challenge response for service: " + hex(service_to_activate))

                    # insulin service activated
                    if (r['records']['Decrypted'] == "\x20\x00\xF7\xF0\x00\x00\x66\x01\x00"):
                        print "INSULIN SERVICE ACTIVATED!!!"
                        # example tbr
                        print "Requesting TBR"
                        reply = build_StartTBR(nonce=r['records']['Nonce'], channel='out', comid=r['records']['ComID'],
                                               key=CLIENT_EMU_OUTGOING_KEY, tbr_percent=90, tbr_mins=15)

        else:
            print r

    x = parse_packet(reply, key=CLIENT_EMU_OUTGOING_KEY)

    log_string = "\nCLIENT EMULATOR REPLY\n" + x['status'] + "\n" + pretty_parsed_string(x) + "\n"

    if (VERBOSE_LOGS == True):
        logger.info("\n" + log_string)
    else:
        print log_string

    return reply


def clientGetDirtyReply(r):
    global CLIENT_STEP
    print "CLIENT STEP: ", CLIENT_STEP
    dirtyreply = DIRTY_CLIENT_SCRIPT[CLIENT_STEP]
    if CLIENT_STEP < len(DIRTY_CLIENT_SCRIPT) - 1:
        CLIENT_STEP += 1
    if (dirtyreply):

        reply = build_DataPacket(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                 key=CLIENT_EMU_OUTGOING_KEY,
                                 channel='out',
                                 data=dirtyreply.replace(" ", "").decode('hex'))
        return reply
    else:
        print "Don't know how to dirty reply"
    return None


### self test

if __name__ == "__main__":
    print "Running client emulator test parameters"
