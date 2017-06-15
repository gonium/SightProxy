import collections
import struct
import hexdump

from crc_algorithms import Crc

crc = Crc(width=16, poly=0x1021,
          reflect_in=True, xor_in=0xffff,
          reflect_out=False, xor_out=0x0000)

PROTOCOL_VERSION = 0x20  # 32

MAGIC_NUMBER = '\x88\xCC\xEE\xFF'

PRIMITIVES = {
    'Magic': '4s',
    'PacketLength': 'L',
    'PacketLengthA': 'H',
    'PacketLengthB': 'h',
    'Version': 'B',
    'Length': 'H',
    'Command': 'B',
    'ComID': 'L',
    'Nonce': '13s',
    'RandomData': '28s',
    'PairingStatus': 'H',
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
    'ConnectionRequest': HEADER + ['CRC', ] + FOOTER,
    'ConnectionResponse': HEADER + ['UnknownByte', 'CRC', ] + FOOTER,
    'KeyRequest': HEADER + ['RandomData', 'TimeStamp', 'PreMasterKey', 'CRC'] + FOOTER,
    'KeyResponse': HEADER + ['RandomData', 'TimeStamp', 'PreMasterKey', 'CRC'] + FOOTER,
    'SynAckResponse': HEADER + FOOTER,
    'VerifyDisplayRequest': HEADER + FOOTER,
    'VerifyDisplayResponse': HEADER + FOOTER,
    'VerifyConfirmRequest': HEADER + ['PairingStatus'] + FOOTER,
    'VerifyConfirmResponse': HEADER + ['PairingStatus'] + FOOTER,
    'Data': HEADER + ['Data'] + FOOTER
}

COMMAND_TYPE = {0x09: 'ConnectionRequest',
                0x0A: 'ConnectionResponse',
                0x0C: 'KeyRequest',
                0x11: 'KeyResponse',
                0x12: 'VerifyDisplayRequest',
                0x14: 'VerifyDisplayResponse',
                0x0E: 'VerifyConfirmRequest',
                0x1E: 'VerifyConfirmResponse',
                0x18: 'SynAckResponse',
                0x03: 'Data',
                }


def pretty(d, indent=0, ascii=False):
    for key, value in d.iteritems():
        if (ascii):
            key = key.capitalize()
        print '\t' * indent + (" " * (20 - len(key))) + str(key) + ":",
        if isinstance(value, dict):
            pretty(value, indent + 1)
        else:
            if isinstance(value, str):
                if (ascii):
                    print '\t' * (indent + 1) + value
                else:
                    print '\t' * (indent + 1) + hexdump.dump(value)
            else:
                print '\t' * (indent + 1) + str(value)


def calculateCrc(packet):
    nupacket = packet[8:len(packet) - 10]  # assume 8 byte header and 8 byte trailer (2 byte checksum)
    return crc.table_driven(nupacket)


def convertToTime(val):
    result = collections.OrderedDict()
    result['year'] = val >> 26 & 0x3f  # up till 2063
    result['month'] = val >> 22 & 0x0f
    result['day'] = val >> 17 & 0x1f
    result['hour'] = val >> 12 & 0x1f
    result['minute'] = val >> 6 & 0x3f
    result['second'] = val & 0x3f
    return result


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


def parse_packet(data):
    result = {'status': 'fail'}

    ########## PARSE HEADER

    s = getStructFromDefinition('Header')

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
    result['Command'] = command_name
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

    if ('CRC' in command_data):
        calc_crc = calculateCrc(data)
        if (calc_crc != command_data['CRC']):
            result['status'] = 'fail'
            result['reason'] = 'Checksum does not match: ' + str(calc_crc) + " vs " + str(command_data['CRC'])
            return result

    pretty(command_data)

    if ('Data' in command_data):
        print
        print "Encapsulated data"
        hexdump.hexdump(command_data['Data'])

    return result

