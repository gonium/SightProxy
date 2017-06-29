import hexdump

PROTOCOL_VERSION = 0x20  # 32

MAGIC_NUMBER = '\x88\xCC\xEE\xFF'
EMPTY_TRAILER = '\x00' * 8
EMPTY_CHALLENGE = '\x00' * 16
EMPTY_NONCE = '\x00' * 13
EMPTY_CRC = 0
EMPTY_LENGTH = 0
NO_ERROR = 0

PRIMITIVES = {
    'Magic': '4s',
    'PacketLength': 'L',
    'PacketLengthA': 'H',
    'PacketLengthB': 'h',
    'Version': 'B',
    'Service': 'B',
    'ChallengeService': 'B',
    'ErrorCode': 'B',
    'AppError': 'H',
    'AppVersion': '2s',
    'AppOpCode': '2s',
    'TwoByteValue': 'H',
    'Length': 'H',
    'Command': 'B',
    'ComID': 'L',
    'Nonce': '13s',
    'RandomData': '28s',
    'PairingStatus': '2s',
    'Challenge': '16s',
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
    'DisconnectRequest': HEADER + FOOTER,
    'VerifyDisplayRequest': HEADER + FOOTER,
    'VerifyDisplayResponse': HEADER + FOOTER,
    'VerifyConfirmRequest': HEADER + ['PairingStatus'] + FOOTER,
    'VerifyConfirmResponse': HEADER + ['PairingStatus'] + FOOTER,
    'Data': HEADER + ['Data'] + FOOTER,

    'ReadStatusParamBlockResponse': ['Version', 'Service'],

    'ServiceChallengeRequest': ['Version', 'Service', 'AppOpCode', 'AppError', 'Challenge'],
    'ServiceActivateResponse': ['Version', 'Service', 'AppOpCode', 'ChallengeService', 'AppVersion', 'Challenge'],
    'ServiceActivateConfirmed': ['Version', 'Service', 'AppOpCode', 'AppError', 'Service', 'AppVersion'],

    'StopTBR': ['Version', 'Service', 'AppOpCode'],
    'StartTBR': ['Version', 'Service', 'AppOpCode', 'TwoByteValue', 'TwoByteValue', 'TwoByteValue', 'CRC'],
    'UpdateTBR': ['Version', 'Service', 'AppOpCode', 'TwoByteValue', 'TwoByteValue', 'TwoByteValue', 'CRC'],

}

SERVICE_TO_PACKET = {
    'Service Activate': 'ServiceActivateResponse'
}

COMMAND_TYPE = {
    0x03: 'Data',
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
    0x1B: 'DisconnectRequest',
}

SERVICE_00_COMMAND_TYPE = {
    0xE8F0: 'Service Version',
    0x0BF0: 'Reconnect Request',
    0x31F3: 'Deactivate All',
    0xF7F0: 'Service Activate',
    0x2EF3: 'Service Deactivate',
    0xD2F3: 'Request Challenge',
    0x14F0: 'Disconnect',
}

SERVICE_0F_COMMAND_TYPE = {
    0xD82E: 'Firmware Versions',
    0x3A03: 'Reservoir Status',
}

SERVICE_33_COMMAND_TYPE = {
    0x561E: 'Read Status Parameter',
}

SERVICE_55_COMMAND_TYPE = {
    0xFF1B: 'Set Date Time'
}

SERVICE_66_COMMAND_TYPE = {
    0xC518: 'Start TBR',
    0x53A4: 'Update TBR',
    0x3918: 'Stop TBR',
}

SERVICE_CLASSIFIER = {
    0x00: SERVICE_00_COMMAND_TYPE,
    0x0F: SERVICE_0F_COMMAND_TYPE,
    0x33: SERVICE_33_COMMAND_TYPE,
    0x55: SERVICE_55_COMMAND_TYPE,
    0x66: SERVICE_66_COMMAND_TYPE,
}

SERVICE_NAME = {
    0x00: "Comms Service",
    0x0F: "Status",
    0x33: "Config Reader",
    0x3C: "Unknown 3C",
    0x55: "Config Writer",
    0x66: "Insulin control",
}


def getCommandValueFromName(name):
    return COMMAND_TYPE.keys()[COMMAND_TYPE.values().index(name)]


def getAppCommandValueFromName(service, name):
    return SERVICE_CLASSIFIER[service].keys()[SERVICE_CLASSIFIER[service].values().index(name)]


def getAppLayerPacket(data):
    res = getAppLayerClassification(data)
    print "App layer classificiation", res
    if (SERVICE_TO_PACKET.has_key(res)):
        return SERVICE_TO_PACKET[res]
    else:
        return None


def getAppLayerClassification(data):
    if (data[0] != '\x20'):
        return "Unknown protocol version!"
    service = ord(data[1])
    if (SERVICE_CLASSIFIER.has_key(service)):
        command = bytesToCommandNumber(data[2:4])
        if SERVICE_CLASSIFIER[service].has_key(command):
            return SERVICE_CLASSIFIER[service][command]
        else:
            return "Unknown command: " + hexdump.dump(data[2:4])
    else:
        return "Unknown service id"


def getAppLayerComponents(data):
    if (data[0] != '\x20'):
        return (None, None)
    service = ord(data[1])
    command = bytesToCommandNumber(data[2:4])
    return (service, command)


def bytesToCommandNumber(command):
    # TODO use struct?
    return ord(command[0]) << 8 | ord(command[1])


def commandNumberToBytes(number):
    return (chr((number >> 8) & 0xFF)) + chr(number & 0xFF)
