import collections

import datetime

from packet_definitions import *
from crc_algorithms import Crc
from cryptograph import *
from keystore import *

crc = Crc(width=16, poly=0x1021,
          reflect_in=True, xor_in=0xffff,
          reflect_out=False, xor_out=0x0000)


def pretty_parsed(x):
    print pretty_parsed_string(x)


def pretty_parsed_string(x):
    if x is None: return
    result = ''
    if (x['status'] == "identified"):
        result += pretty_string(x['records'])
    else:
        result += x['reason'] + "\n"
    if ('valid' in x):
        result += "         valid:  " + str(x['valid'])
    return result


def pretty(d, indent=0, ascii=False, VERBOSE_PRETTY=False):
    if (d == None):
        print "None type passed to pretty print!"
        return
    print pretty_string(d, indent=indent, ascii=ascii, VERBOSE_PRETTY=VERBOSE_PRETTY),


def pretty_string(d, indent=0, ascii=False, VERBOSE_PRETTY=False):
    IMPORTANT_PRETTY_KEYS = ['Command', 'Length', 'Nonce', 'Decrypted', 'Service', 'AppOpCode', 'AppVersion',
                             'Challenge']
    result = ''
    for key, value in d.iteritems():
        if (ascii):
            key = key.capitalize()
        if (VERBOSE_PRETTY or key in IMPORTANT_PRETTY_KEYS):
            result += '  ' * indent + (" " * ((indent * 2) + 14 - len(key))) + str(key) + ": "
            if isinstance(value, dict):
                result += '\n'
                result += pretty_string(value, indent + 1) + '\n'
            else:
                if isinstance(value, str):
                    if (ascii):
                        result += ' ' * (1) + value + '\n'
                    else:
                        if (key == 'Decrypted'):
                            app_classification = getAppLayerClassification(value)
                            # stored here as the next packet is not identified
                            if (app_classification == 'Request Challenge') and len(value) == 7:
                                key_set("last-requested-challenge-service", ord(value[4]))
                                key_set("last-requested-challenge-version", bytesToCommandNumber(value[5:7]))
                            result += app_classification + "   "
                        result += ' ' * (1) + hexdump.dump(value) + '\n'
                else:
                    if (key == 'Service'):
                        result += ' ' * (1) + hex(value) + " "

                    if (key == 'Command'):
                        result += ' ' * (1) + hex(value) + " "
                        if (COMMAND_TYPE.has_key(value)):
                            result += COMMAND_TYPE[value]
                        else:
                            result += "UNKNOWN!"
                    else:
                        result += ' ' * (1) + str(value)
                    result += '\n'
    return result


def calculateCrc(packet):
    nupacket = packet[8:len(packet) - 10]  # assume 8 byte header and 8 byte trailer (2 byte checksum)
    return crc.table_driven(nupacket)


def calculateCrcForSubFrame(packet):
    nupacket = packet[4:len(packet) - 2]  # assume 4 byte header and 2 byte checksum
    return crc.table_driven(nupacket)


def calculateCrcBytes(packet):
    crc = calculateCrc(packet)
    s = struct.Struct("<" + PRIMITIVES['CRC'])
    return s.pack(crc)


def calculateCrcForString(frame):
    output = crc.table_driven(frame)
    s = struct.Struct("<" + PRIMITIVES['CRC'])
    return s.pack(output)


def calculatePacketLengths(packet):
    if isinstance(packet, str):
        l = len(packet)
    else:
        l = packet
    return (l - 8, ((l - 8) * -1) - 1)


def injectTagForPacket(packet, key, payload=''):
    if (key == None):
        print "Key not set when injecting tag!"
        return None

    # header = packet[8:29]
    # nonce = packet[16:19]
    # tag = produceCCMtag(nonce=nonce, payload=payload, header=header, key=key)
    tag = produceTagForPacket(packet, key, payload)
    return packet[:len(packet) - 8] + tag


def produceTagForPacket(packet, key, payload=''):
    if (key == None):
        print "Key not set when generating tag!"
        return None

    header = packet[8:29]
    nonce = packet[16:29]
    tag = produceCCMtag(nonce=nonce, payload=payload, header=header, key=key)
    return tag


def checkTagForPacket(packet, key, payload='', tag=None):
    if (key == None):
        print "Key not set when checking tag!"
        return None

    if (tag == None):
        tag = packet[len(packet) - 8:]

    result = produceTagForPacket(packet, key, payload=payload)
    if (result == tag):
        return True
    else:
        print "CCM TAG does not match for packet!"
        return False


def reEncryptBlock(nonce=None, payload=None, key=None, packet=None, channel=None):
    if (packet == None):
        print "NO PACKET TO REENCRYPT"
        return None
    if (key == None):
        print "NO KEY TO REENCRYPT WITH"
        return None

    comid = key_get(channel + '-comid')

    if (comid == None):
        print "NO COMID TO REENCRYPT WITH"

    comid_bytes = getStructFromPrimitive('ComID').pack(comid)
    packet = packet[:12] + comid_bytes + packet[16:]

    nonce = incrementNonce(packet[16:29], channel=channel)
    packet = packet[:16] + nonce + packet[29:]
    crypted_data = CTRmodeEncryptData(plain=payload, nonce=nonce, key=key)
    packet = packet[:-(8 + len(payload))] + crypted_data + '\x00' * 8
    packet = injectTagForPacket(packet, key=key, payload=payload)
    return packet


def convertToTime(val):
    result = collections.OrderedDict()
    result['year'] = val >> 26 & 0x3f  # up till 2063
    result['month'] = val >> 22 & 0x0f
    result['day'] = val >> 17 & 0x1f
    result['hour'] = val >> 12 & 0x1f
    result['minute'] = val >> 6 & 0x3f
    result['second'] = val & 0x3f
    return result


def getCurrentTimeStamp():
    now = datetime.datetime.now()
    val = (now.year % 100 & 0x3f) << 26 | (
                                              now.month & 0x0f) << 22 | (
                                                                            now.day & 0x1f) << 17 | (
                                                                                                        now.hour & 0x1f) << 12 | (
                                                                                                                                     now.minute & 0x3f) << 6 | (
              now.second & 0x3f)
    return val


def produceComID(comid):
    return (comid & 0xffff) | comid << 16


def getStructFromDefinition(definition):
    result = "<"  # little endian
    for item in DEFINITION[definition]:
        result += PRIMITIVES[item]
    # print "built struct: ", result
    return struct.Struct(result)


def getStructFromPrimitive(primitive):
    result = "<" + PRIMITIVES[primitive]
    return struct.Struct(result)


def unpackedToDictionary(unpacked_data, definition):
    result = collections.OrderedDict()
    for i, a in enumerate(unpacked_data):
        index = DEFINITION[definition][i]
        result[index] = a
        # TODO we may not actually want to do this here
        if (index == 'TimeStamp'):
            result['TimeStampConverted'] = convertToTime(int(a))

    return result


def splitByMTU(data, mtu):
    while data:
        yield data[:mtu]
        data = data[mtu:]


def getPipelinedPacket(data, pipeline=None):
    assert (not pipeline is None)
    if (len(pipeline[0]) > 0):
        print "pipeline size: " + str(len(pipeline[0]))
    data = pipeline[0] + data
    s = getStructFromDefinition('TopHeader')
    if data == None or len(data) < s.size:
        # print "Not enough data for pipeline processing"
        return None

    pipeline[0] = ''
    (magic, packet_size) = s.unpack(data[0:s.size])
    packet_size += 8

    if (len(data) < packet_size):
        # too small
        print "Storing " + str(len(data)) + " bytes in the pipeline"
        pipeline[0] += data
        return None
    elif (len(data) > packet_size):
        print "Storing " + str(len(data) - packet_size) + " remaindered data bytes in the pipeline"
        pipeline[0] = data[packet_size:]
        return data[:packet_size]
    else:
        return data


def parse_packet(data, key=None, logger=None, loghelper='', app_logger=None):
    # print "Parse packet key: ",hd(key)
    has_decrypted = False
    result = {'status': 'fail'}

    ########## PARSE HEADER

    s = getStructFromDefinition('Header')

    if (data == None):
        print "NO DATA PASSED"
        result['reason'] = 'No data passed to parse packet!'
        return result

    if len(data) < s.size:
        result['reason'] = 'not enough data for a header'
        return result

    header_data = unpackedToDictionary(s.unpack(data[0:s.size]), 'Header')
    # print header_data

    if (header_data['Magic'] != MAGIC_NUMBER):
        result['reason'] = 'magic number doesnt match'
        return result

    if (header_data['Version'] != PROTOCOL_VERSION):
        result['reason'] = 'protocol version unknown'
        return result

    if (not header_data['Command'] in COMMAND_TYPE):
        result['reason'] = 'unknown command ' + str(header_data['Command'])
        return result

    command_name = COMMAND_TYPE[header_data['Command']]
    # print
    # print "PACKET COMMAND: ", command_name
    result['command'] = command_name
    result['status'] = 'identified'

    if (command_name == 'Data'):
        PRIMITIVES['Data'] = str(header_data['Length']) + "s"  # dynamic size

    # PARSE FULL PACKET
    s = getStructFromDefinition(command_name)
    if len(data) < s.size:
        result['status'] = 'fail'
        result['reason'] = 'not enough data for ' + command_name + ' ' + str(len(data)) + " vs " + str(s.size)
        return result

    if (len(data) > s.size):
        result['notes'] = str(len(data) - s.size) + " extra bytes in packet"

    command_data = unpackedToDictionary(s.unpack(data[0:s.size]), command_name)

    if ('Data' in command_data and key):
        # TODO verify message authentication code
        command_data['Decrypted'] = CTRmodeEncryptData(plain=command_data['Data'], nonce=command_data['Nonce'], key=key)
        if command_data['Decrypted']:
            has_decrypted = True

    if ('PairingStatus' in command_data and key):
        # TODO verify message authentication code
        command_data['Decrypted'] = CTRmodeEncryptData(plain=command_data['PairingStatus'], nonce=command_data['Nonce'],
                                                       key=key)
        if command_data['Decrypted']:
            has_decrypted = True

    if ('Trailer' in command_data and command_data['Trailer'] != EMPTY_TRAILER and result[
        'command'] != "ConnectionRequest"):
        pl = ''
        if 'Decrypted' in command_data:
            pl = command_data['Decrypted']
        result['valid'] = checkTagForPacket(data, key, payload=pl, tag=None)

    if ('CRC' in command_data):
        calc_crc = calculateCrc(data)
        if (calc_crc != command_data['CRC']):
            result['status'] = 'fail'
            result['reason'] = 'Checksum does not match: ' + str(calc_crc) + " vs " + str(command_data['CRC'])
            return result

    result['records'] = command_data
    if (logger != None and has_decrypted):
        processAnyDecryptedData(logger=logger, result=result, loghelper=loghelper, app_logger=app_logger)
    return result


def processAnyDecryptedData(logger=None, result=None, loghelper='', app_logger=None):
    if (result != None):
        if 'records' in result:
            r = result['records']
            if 'Decrypted' in r:
                if ('valid' in result and result['valid'] == False):
                    insert = loghelper + " CCM INVALID!! "
                else:
                    insert = loghelper
                logstring = insert + "++++ " + result['command'] + " =\n" + hexdump.hexdump(r['Decrypted'],
                                                                                            result="return") + "\n"
                logstring = insert.join(logstring.splitlines(True))
                # logger.info(logstring) # gets from app_logger
                if not app_logger is None:
                    app_logger.info(logstring)


### Packet builders

def build_ConnectionRequest(comid=0):
    packet_type = 'ConnectionRequest'
    s = getStructFromDefinition(packet_type)

    connection_request_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_request_length + 2,
                    produceComID(comid), EMPTY_NONCE, EMPTY_CRC, EMPTY_TRAILER)

    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_request_length + 2,
                    produceComID(comid), EMPTY_NONCE, calculateCrc(packet), EMPTY_TRAILER)

    # Assuming trailer contents doesn't matter here
    return packet


def build_ConnectionResponse(comid=0):
    packet_type = 'ConnectionResponse'
    s = getStructFromDefinition(packet_type)
    unknown_byte = 0  # TODO needs to be checked
    connection_response_length = 3
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_response_length,
                    produceComID(comid), EMPTY_NONCE, unknown_byte, EMPTY_CRC, EMPTY_TRAILER)
    # add crc and lengths

    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_response_length,
                    produceComID(comid), EMPTY_NONCE, unknown_byte, calculateCrc(packet), EMPTY_TRAILER)

    return packet


def build_SynRequest(comid=0, nonce=None, channel=None, key=None):
    packet_type = 'SynRequest'
    s = getStructFromDefinition(packet_type)

    nonce = incrementNonce(nonce, channel=channel)
    connection_response_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_response_length,
                    comid, nonce, EMPTY_TRAILER)
    packet = injectTagForPacket(packet, key=key, payload='')
    return packet


def build_SynAckResponse(comid=0, nonce=None, channel=None, key=None):
    packet_type = 'SynAckResponse'
    s = getStructFromDefinition(packet_type)
    # TODO this results in error reply
    nonce = incrementNonce(nonce, channel=channel)
    connection_response_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_response_length,
                    comid, nonce, EMPTY_TRAILER)
    packet = injectTagForPacket(packet, key=key, payload='')
    return packet


def build_VerifyDisplayRequest(comid=0, nonce=None, key=None, channel=None):
    packet_type = 'VerifyDisplayRequest'
    nonce = incrementNonce(nonce, channel=channel)
    s = getStructFromDefinition(packet_type)

    response_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    response_length, comid, nonce,
                    EMPTY_TRAILER)

    packet = injectTagForPacket(packet, key=key, payload='')
    return packet


def build_VerifyDisplayResponse(comid=0, nonce=None, key=None, channel=None):
    packet_type = 'VerifyDisplayResponse'
    s = getStructFromDefinition(packet_type)
    nonce = incrementNonce(nonce, channel=channel)
    response_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    response_length,
                    comid, nonce, EMPTY_TRAILER)

    packet = injectTagForPacket(packet, key=key)
    return packet


def build_VerifyConfirmRequest(comid=0, nonce=None, key=None, channel=None):
    packet_type = 'VerifyConfirmRequest'
    nonce = incrementNonce(nonce, channel=channel)
    pairing_confirmed = '\x3b\x2e'
    pairing_confirmed_crypted = CTRmodeEncryptData(plain=pairing_confirmed, nonce=nonce, key=key)
    s = getStructFromDefinition(packet_type)

    response_length = 2
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    response_length, comid, nonce,
                    pairing_confirmed_crypted, EMPTY_TRAILER)

    packet = injectTagForPacket(packet, key=key, payload=pairing_confirmed)
    return packet


def build_DataPacket(comid=0, nonce=None, key=None, channel=None, data=None):
    packet_type = 'Data'
    nonce = incrementNonce(nonce, channel=channel)
    data_crypted = CTRmodeEncryptData(plain=data, nonce=nonce, key=key)
    PRIMITIVES['Data'] = str(len(data)) + "s"  # dynamic size
    s = getStructFromDefinition(packet_type)

    response_length = len(data)
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    response_length, comid, nonce,
                    data_crypted, EMPTY_TRAILER)

    packet = injectTagForPacket(packet, key=key, payload=data)
    return packet


def build_VerifyConfirmResponse(comid=0, nonce=None, key=None, channel=None):
    packet_type = 'VerifyConfirmResponse'
    nonce = incrementNonce(nonce, channel=channel)
    pairing_confirmed = '\x3b\x2e'
    pairing_confirmed_crypted = CTRmodeEncryptData(plain=pairing_confirmed, nonce=nonce, key=key)
    s = getStructFromDefinition(packet_type)

    response_length = 2
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    response_length, comid, nonce,
                    pairing_confirmed_crypted, EMPTY_TRAILER)

    packet = injectTagForPacket(packet, key=key, payload=pairing_confirmed)
    return packet


def build_KeyRequest(comid=1, random_data=None, our_public_key=None, lazy_timestamp=None,
                     nonce=None):
    packet_type = 'KeyRequest'
    s = getStructFromDefinition(packet_type)
    connection_response_length = 290
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION,
                    getCommandValueFromName(packet_type), connection_response_length,
                    comid, EMPTY_NONCE,
                    random_data, lazy_timestamp, our_public_key,
                    EMPTY_CRC, EMPTY_TRAILER)

    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_response_length,
                    comid, EMPTY_NONCE,
                    random_data, lazy_timestamp, our_public_key,
                    calculateCrc(packet), EMPTY_TRAILER)

    return packet


def build_KeyResponse(comid=0, random_data=None, secret_key=None, peer_public_key=None, lazy_timestamp=None,
                      nonce=None, channel=None):
    packet_type = 'KeyResponse'
    s = getStructFromDefinition(packet_type)
    nonce = incrementNonce(nonce, channel=channel)
    connection_response_length = 290
    pub_key = publicKeyFromString(peer_public_key)
    # print pub_key

    encrypted_data = encryptWithPeerRSAkey(secret_key, pub_key)

    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION,
                    getCommandValueFromName(packet_type), connection_response_length,
                    produceComID(comid), nonce,
                    random_data, lazy_timestamp, encrypted_data,
                    EMPTY_CRC, EMPTY_TRAILER)
    # add crc and lengths

    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_response_length,
                    produceComID(comid), nonce,
                    random_data, lazy_timestamp, encrypted_data,
                    calculateCrc(packet), EMPTY_TRAILER)

    return packet


### self tests

def hdwrap(data):
    if (data != None):
        hexdump.hexdump(data)


if __name__ == "__main__":
    print "Running packet factory test parameters"
    from test_packets import *
