import collections

import datetime

from crc_algorithms import Crc
from cryptograph import *

crc = Crc(width=16, poly=0x1021,
          reflect_in=True, xor_in=0xffff,
          reflect_out=False, xor_out=0x0000)

PROTOCOL_VERSION = 0x20  # 32

MAGIC_NUMBER = '\x88\xCC\xEE\xFF'
EMPTY_TRAILER = '\x00' * 8
EMPTY_NONCE = '\x00' * 13
EMPTY_CRC = 0
EMPTY_LENGTH = 0

PRIMITIVES = {
    'Magic': '4s',
    'PacketLength': 'L',
    'PacketLengthA': 'H',
    'PacketLengthB': 'h',
    'Version': 'B',
    'ErrorCode': 'B',
    'Length': 'H',
    'Command': 'B',
    'ComID': 'L',
    'Nonce': '13s',
    'RandomData': '28s',
    'PairingStatus': '2s',
    'TimeStamp': 'L',
    'TimeString': '4s',
    'PreMasterKey': '256s',
    'UnknownByte': 'B',
    'CRC': 'H',
    'Trailer': '8s',
    'Data': '0s'
}
TOP_HEADER = ['Magic', 'PacketLengthA']
HEADER = TOP_HEADER + ['PacketLengthB', 'Version', 'Command', 'Length', 'ComID', 'Nonce']
FOOTER = ['Trailer']

DEFINITION = {
    'Header': HEADER,
    'TopHeader': TOP_HEADER,
    'Error': HEADER + ['ErrorCode'] + FOOTER,
    'ConnectionRequest': HEADER + ['CRC', ] + FOOTER,
    'ConnectionResponse': HEADER + ['UnknownByte', 'CRC', ] + FOOTER,
    'KeyRequest': HEADER + ['RandomData', 'TimeStamp', 'PreMasterKey', 'CRC'] + FOOTER,
    'KeyResponse': HEADER + ['RandomData', 'TimeStamp', 'PreMasterKey', 'CRC'] + FOOTER,
    'SynRequest': HEADER + FOOTER,
    'SynAckResponse': HEADER + FOOTER,
    'VerifyDisplayRequest': HEADER + FOOTER,
    'VerifyDisplayResponse': HEADER + FOOTER,
    'VerifyConfirmRequest': HEADER + ['PairingStatus'] + FOOTER,
    'VerifyConfirmResponse': HEADER + ['PairingStatus'] + FOOTER,
    'Data': HEADER + ['Data'] + FOOTER
}

COMMAND_TYPE = {
    0x06: 'Error',
    0x09: 'ConnectionRequest',
    0x0A: 'ConnectionResponse',
    0x0C: 'KeyRequest',
    0x11: 'KeyResponse',
    0x12: 'VerifyDisplayRequest',
    0x14: 'VerifyDisplayResponse',
    0x0E: 'VerifyConfirmRequest',
    0x1E: 'VerifyConfirmResponse',
    0x17: 'SynRequest',
    0x18: 'SynAckResponse',
    0x03: 'Data',
}


def getCommandValueFromName(name):
    return COMMAND_TYPE.keys()[COMMAND_TYPE.values().index(name)]


def pretty_parsed(x):
    print pretty_parsed_string(x)
    # if x is None: return
    # if (x['status'] == "identified"):
    #     pretty(x['records'])
    # else:
    #     print x['reason']
    # if ('valid' in x):
    #     print "         valid:  " + str(x['valid'])
    # print


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


def pretty(d, indent=0, ascii=False):
    print pretty_string(d, indent=indent, ascii=ascii),
    # for key, value in d.iteritems():
    #     if (ascii):
    #         key = key.capitalize()
    #     print '  ' * indent + (" " * ((indent * 2) + 14 - len(key))) + str(key) + ":",
    #     if isinstance(value, dict):
    #         print
    #         pretty(value, indent + 1)
    #     else:
    #         if isinstance(value, str):
    #             if (ascii):
    #                 print ' ' * (1) + value
    #             else:
    #                 print ' ' * (1) + hexdump.dump(value)
    #         else:
    #             print ' ' * (1) + str(value)


def pretty_string(d, indent=0, ascii=False):
    result = ''
    for key, value in d.iteritems():
        if (ascii):
            key = key.capitalize()
        result += '  ' * indent + (" " * ((indent * 2) + 14 - len(key))) + str(key) + ": "
        if isinstance(value, dict):
            result += '\n'
            result += pretty_string(value, indent + 1) + '\n'
        else:
            if isinstance(value, str):
                if (ascii):
                    result += ' ' * (1) + value + '\n'
                else:
                    result += ' ' * (1) + hexdump.dump(value) + '\n'
            else:

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


def calculateCrcBytes(packet):
    crc = calculateCrc(packet)
    s = struct.Struct("<" + PRIMITIVES['CRC'])
    return s.pack(crc)


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
    nonce = packet[16:19]
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


def reEncryptBlock(nonce=None, payload=None, key=None, packet=None):
    if (packet == None):
        print "NO PACKET TO REENCRYPT"
        return None
    if (key == None):
        print "NO KEY TO REENCRYPT WITH"
        return None

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
    data = pipeline + data
    s = getStructFromDefinition('TopHeader')
    if data == None or len(data) < s.size:
        # print "Not enough data for pipeline processing"
        return None

    pipeline = ''
    (magic, packet_size) = s.unpack(data[0:s.size])
    packet_size += 8

    if (len(data) < packet_size):
        # too small
        print "Storing " + str(len(data)) + " bytes in the pipeline"
        pipeline += data
        return None
    elif (len(data) > packet_size):
        print "Storing " + str(len(data) - packet_size) + " remaindered data bytes in the pipeline"
        pipeline += data[packet_size:]
        return data[:packet_size]
    else:
        return data


def parse_packet(data, key=None, logger=None):
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
        processAnyDecryptedData(logger=logger, result=result)
    return result


def processAnyDecryptedData(logger=None, result=None):
    if (result != None):
        if 'records' in result:
            r = result['records']
            if 'Decrypted' in r:
                if ('valid' in result and result['valid'] == False):
                    insert = "CCM INVALID!! "
                else:
                    insert = ""
                logger.info(
                    insert + "++++ " + result['command'] + " =\n" + hexdump.hexdump(r['Decrypted'],
                                                                                    result="return") + "\n")


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


def build_SynAckResponse(comid=0, nonce=None):
    packet_type = 'SynAckResponse'
    s = getStructFromDefinition(packet_type)
    # TODO this results in error reply
    nonce = incrementNonce(nonce)
    connection_response_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    connection_response_length,
                    comid, nonce, EMPTY_TRAILER)

    return packet


def build_VerifyDisplayRequest(comid=0, nonce=None, key=None):
    packet_type = 'VerifyDisplayRequest'
    nonce = incrementNonce(nonce)
    s = getStructFromDefinition(packet_type)

    response_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    response_length, comid, nonce,
                    EMPTY_TRAILER)

    packet = injectTagForPacket(packet, key=key, payload='')
    return packet


def build_VerifyDisplayResponse(comid=0, nonce=None, key=None):
    packet_type = 'VerifyDisplayResponse'
    s = getStructFromDefinition(packet_type)
    nonce = incrementNonce(nonce)
    response_length = 0
    (pla, plb) = calculatePacketLengths(s.size)
    packet = s.pack(MAGIC_NUMBER, pla, plb, PROTOCOL_VERSION, getCommandValueFromName(packet_type),
                    response_length,
                    comid, nonce, EMPTY_TRAILER)

    packet = injectTagForPacket(packet, key=key)
    return packet


def build_VerifyConfirmRequest(comid=0, nonce=None, key=None):
    packet_type = 'VerifyConfirmRequest'
    nonce = incrementNonce(nonce)
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


def build_VerifyConfirmResponse(comid=0, nonce=None, key=None):
    packet_type = 'VerifyConfirmResponse'
    nonce = incrementNonce(nonce)
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
                      nonce=None):
    packet_type = 'KeyResponse'
    s = getStructFromDefinition(packet_type)
    nonce = incrementNonce(nonce)
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

if __name__ == "__main__":
    print "Running packet factory test parameters"


    def hdwrap(data):
        if (data != None):
            hexdump.hexdump(data)


    from test_packets import *
