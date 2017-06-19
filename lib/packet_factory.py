import collections

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
HEADER = ['Magic', 'PacketLengthA', 'PacketLengthB', 'Version', 'Command', 'Length', 'ComID', 'Nonce']
FOOTER = ['Trailer']

DEFINITION = {
    'Header': HEADER,
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


def pretty(d, indent=0, ascii=False):
    for key, value in d.iteritems():
        if (ascii):
            key = key.capitalize()
        print '  ' * indent + (" " * ((indent * 2) + 14 - len(key))) + str(key) + ":",
        if isinstance(value, dict):
            print
            pretty(value, indent + 1)
        else:
            if isinstance(value, str):
                if (ascii):
                    print ' ' * (1) + value
                else:
                    print ' ' * (1) + hexdump.dump(value)
            else:
                print ' ' * (1) + str(value)


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

    header = packet[8:29]
    nonce = packet[16:19]
    tag = produceCCMtag(nonce=nonce, payload=payload, header=header, key=key)
    return packet[:len(packet) - 8] + tag


def convertToTime(val):
    result = collections.OrderedDict()
    result['year'] = val >> 26 & 0x3f  # up till 2063
    result['month'] = val >> 22 & 0x0f
    result['day'] = val >> 17 & 0x1f
    result['hour'] = val >> 12 & 0x1f
    result['minute'] = val >> 6 & 0x3f
    result['second'] = val & 0x3f
    return result


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


def parse_packet(data, key=None):
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

    # Todo check length - continuation for multi part

    if (header_data['Version'] != PROTOCOL_VERSION):
        result['reason'] = 'protocol version unknown'
        return result

    if (not header_data['Command'] in COMMAND_TYPE):
        result['reason'] = 'unknown command ' + str(header_data['Command'])
        return result

    command_name = COMMAND_TYPE[header_data['Command']]
    print
    print "PACKET COMMAND: ", command_name
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

    if ('Data' in command_data):
        # TODO verify message authentication code
        command_data['Decrypted'] = CTRmodeEncryptData(plain=command_data['Data'], nonce=command_data['Nonce'], key=key)

    if ('CRC' in command_data):
        calc_crc = calculateCrc(data)
        if (calc_crc != command_data['CRC']):
            result['status'] = 'fail'
            result['reason'] = 'Checksum does not match: ' + str(calc_crc) + " vs " + str(command_data['CRC'])
            return result

    result['records'] = command_data

    return result


### Packet builders

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
