from keystore import *
from packet_factory import *
from app_factory import *
from cryptograph import *
from dirtyemulator import *
# from test_packets import *

# pump emulator

PUMP_RANDOM_DATA = None
PEER_RANDOM_DATA = None
PEER_PUBLIC_KEY = None
SECRET_KEY = None
PUMP_EMU_INCOMING_KEY = None
PUMP_EMU_OUTGOING_KEY = None

PUMP_APP_EMULATION = False

LAST_CHALLENGE = None

T_FILE = "/tmp/cx.trigger"
R_FOLDER = "/tmp/cx-reply-"

def init_pump_emulator():
    global PUMP_APP_EMULATION
    PUMP_APP_EMULATION = boolean_get('setting-PUMP_APP_EMULATION')

def generate_pump_response(data, logger=None, VERBOSE_LOGS=True):
    global HIGHEST_NONCE, LAST_CHALLENGE
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

        if (r['command'] == 'SynRequest'):
            print "Replying with SynAckResponse"
            # TODO CHECK COMID

            PUMP_EMU_INCOMING_KEY = key_get('real_client_incoming')
            PUMP_EMU_OUTGOING_KEY = key_get('real_client_outgoing')

            if (PUMP_EMU_OUTGOING_KEY == None):
                PUMP_EMU_OUTGOING_KEY = '\x00' * 16

            reply = build_SynAckResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                         channel='in',
                                         key=PUMP_EMU_OUTGOING_KEY)

        if (r['command'] == 'ConnectionRequest'):
            HIGHEST_NONCE['in'] = 0
            print "Replying with ConnectionResponse"
            reply = build_ConnectionResponse(comid=r['records']['ComID'])

        if (r['command'] == 'KeyRequest'):
            print "Replying with KeyResponse"
            PEER_PUBLIC_KEY = r['records']['PreMasterKey']
            PEER_RANDOM_DATA = r['records']['RandomData']
            (PUMP_RANDOM_DATA, SECRET_KEY) = createKeyData()
            reply = build_KeyResponse(comid=r['records']['ComID'],
                                      random_data=PUMP_RANDOM_DATA, secret_key=SECRET_KEY,
                                      peer_public_key=PEER_PUBLIC_KEY,
                                      lazy_timestamp=r['records']['TimeStamp'],
                                      nonce=r['records']['Nonce'],
                                      channel='in')
            (PUMP_EMU_OUTGOING_KEY, PUMP_EMU_INCOMING_KEY) = deriveKeys(SECRET_KEY, KEY_SEED,
                                                                        PEER_RANDOM_DATA + PUMP_RANDOM_DATA)
            key_set('real_client_incoming', PUMP_EMU_INCOMING_KEY)
            key_set('real_client_outgoing', PUMP_EMU_OUTGOING_KEY)
            logger.info("PUMPEMU OUTGOING_KEY: " + hd(PUMP_EMU_OUTGOING_KEY))
            logger.info("PUMPEMU INCOMING_KEY: " + hd(PUMP_EMU_INCOMING_KEY))

        if (r['command'] == 'VerifyDisplayRequest'):
            print "Replying with VerifyDisplayResponse"
            reply = build_VerifyDisplayResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                key=PUMP_EMU_OUTGOING_KEY,
                                                channel='in')

        if (r['command'] == 'VerifyConfirmRequest'):
            print "Replying with VerifyConfirmResponse"
            reply = build_VerifyConfirmResponse(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                key=PUMP_EMU_OUTGOING_KEY,
                                                channel='in')
            key_set("in-comid", r['records']['ComID'])

        if PUMP_APP_EMULATION:
            if (r['command'] == 'Data'):
                print "Attempting to process data packet"
                dirtyreply = getDirtyPumpReply(r['records']['Decrypted'])
                if (dirtyreply):
                    reply = build_DataPacket(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                             key=PUMP_EMU_OUTGOING_KEY,
                                             channel='in',
                                             data=dirtyreply.replace(" ", "").decode('hex'))
                else:

                    app_parsed = parse_app_packet(r['records']['Decrypted'])
                    if (app_parsed['status'] == 'identified'):
                        pretty(app_parsed['records'], VERBOSE_PRETTY=True)

                    (service, command) = getAppLayerComponents(r['records']['Decrypted'])
                    if (service == 0x00 and command == 0xD2F3):

                        challenge = None
                        if (os.path.exists(T_FILE)):
                            f = open(T_FILE, "rb")
                            tr = f.read()
                            f.close()
                            try:
                                challenge = tr.decode('hex')
                            except:
                                print "Exception decoding"
                                challenge = None
                            if len(challenge) != 16:
                                print "invalid length"
                                challenge = None
                        if (challenge != None):
                            LAST_CHALLENGE = challenge
                            logger.critical("SENDING CHALLENGE REQUEST: " + hd(
                                r['records']['Decrypted']) + " " + hd(
                                challenge))

                        reply = build_AppServiceChallenge(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                          key=PUMP_EMU_OUTGOING_KEY,
                                                          channel='in', challenge=challenge,
                                                          )

                    if (service == 0x00 and command == 0xF7F0):
                        logger.critical(
                            "RECEIVED CHALLENGE RESPONSE: " + hex(app_parsed['records']['ChallengeService']) + " " + hd(
                                app_parsed['records']['Challenge']))
                        print "Generating challenge accepted"
                        if (LAST_CHALLENGE != None):
                            f = open(R_FOLDER + hd(LAST_CHALLENGE).upper(), "wb")
                            f.write(hd(app_parsed['records']['Challenge']))
                            f.close()
                        print "building service activate confirmed"
                        reply = build_ServiceActivateConfirmed(comid=r['records']['ComID'], nonce=r['records']['Nonce'],
                                                               key=PUMP_EMU_OUTGOING_KEY,
                                                               channel='in',
                                                               activated_service=app_parsed['records'][
                                                                   'ChallengeService']
                                                               )
                    else:
                        print "Don't know how to reply"

    else:
        print r

    x = parse_packet(reply, key=PUMP_EMU_OUTGOING_KEY)
    log_string = "\nPUMP EMULATOR REPLY\n" + x['status'] + "\n" + pretty_parsed_string(x) + "\n"


    if (VERBOSE_LOGS == True):
        logger.info("\n" + log_string)
    else:
        print log_string

    return reply


### self test

if __name__ == "__main__":
    print "Running pump emulator test parameters"
