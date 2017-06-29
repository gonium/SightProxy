from packet_definitions import *
from packet_factory import *


def parse_app_packet(data):
    result = {'status': 'fail'}

    (service, command) = getAppLayerComponents(data)
    print "Service Command", service, command
    command_name = getAppLayerPacket(data)
    print "command name", command_name
    if (command_name != None):
        s = getStructFromDefinition(command_name)
        if len(data) < s.size:
            result['status'] = 'fail'
            result['reason'] = 'not enough data for ' + command_name + ' ' + str(len(data)) + " vs " + str(s.size)
            return result

        if (len(data) > s.size):
            result['notes'] = str(len(data) - s.size) + " extra bytes in packet"

        command_data = unpackedToDictionary(s.unpack(data[0:s.size]), command_name)
        result['command'] = command_name
        result['status'] = 'identified'
        result['records'] = command_data

    else:
        print "Cannot parse app layer packet: ", hex(service), hex(command)

    return result


def build_AppServiceChallenge(nonce=None, channel=None, comid=None, key=None, challenge=None):
    packet_type = 'ServiceChallengeRequest'
    if (challenge == None):
        challenge = getRandomBytes(16)
    s = getStructFromDefinition(packet_type)
    service = 0x00
    app_opcode = getAppCommandValueFromName(service, 'Request Challenge')
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode), NO_ERROR, challenge)
    packet = build_DataPacket(comid=comid, nonce=nonce,
                              key=key,
                              channel=channel,
                              data=app_packet)
    return packet


def build_AppServiceChallengeResponse(nonce=None, channel=None, comid=None, key=None, service_to_activate=None,
                                      service_version=None, challenge_response=None):
    packet_type = 'ServiceActivateResponse'
    s = getStructFromDefinition(packet_type)
    service = 0x00
    app_opcode = getAppCommandValueFromName(service, 'Service Activate')
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode), service_to_activate,
                        commandNumberToBytes(service_version), challenge_response)
    packet = build_DataPacket(comid=comid, nonce=nonce,
                              key=key,
                              channel=channel,
                              data=app_packet)
    return packet


def build_ServiceActivateConfirmed(nonce=None, channel=None, comid=None, key=None, activated_service=None):
    s = getStructFromDefinition('ServiceActivateConfirmed')
    service = 0x00

    SERVICE_VERSIONSA = {0x55: 0x0201,
                         0x66: 0x0100,
                         0x0F: 0x0100,
                         0x3C: 0x0201, }

    SERVICE_VERSIONSB = {0x55: 0x0200,
                         0x66: 0x0100,
                         0x0F: 0x0100,
                         0x3C: 0x0200, }

    SERVICE_VERSIONS = SERVICE_VERSIONSB

    app_opcode = getAppCommandValueFromName(service, 'Service Activate')
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode), NO_ERROR, activated_service,
                        commandNumberToBytes(SERVICE_VERSIONS[activated_service]))

    packet = build_DataPacket(comid=comid, nonce=nonce,
                              key=key,
                              channel=channel,
                              data=app_packet)
    return packet


def build_StopTBR(nonce=None, channel=None, comid=None, key=None):
    s = getStructFromDefinition('StopTBR')
    service = 0x66
    app_opcode = getAppCommandValueFromName(service, 'Stop TBR')
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode))
    packet = build_DataPacket(comid=comid, nonce=nonce,
                              key=key,
                              channel=channel,
                              data=app_packet)
    return packet


def validate_tbr_parameters(tbr_percent=None, tbr_mins=None):
    if (tbr_mins == None):
        print "tbr mins is None"
        return False
    if (tbr_percent == None):
        print "tbr percent None"
        return False
    if (tbr_mins < 10):
        return False
    if (tbr_mins > 60):
        return False
    if (tbr_percent < 0):
        return False
    if (tbr_percent > 200):
        return False
    return True


def build_StartTBR(nonce=None, channel=None, comid=None, key=None, tbr_percent=None, tbr_mins=None, testing=False):
    s = getStructFromDefinition('StartTBR')

    if (not testing and not validate_tbr_parameters(tbr_percent=tbr_percent, tbr_mins=tbr_mins)):
        print "Validation failed for TBR parameters"
        return None

    service = 0x66
    id_code = 0x1F
    app_opcode = getAppCommandValueFromName(service, 'Start TBR')
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode), tbr_percent, tbr_mins, id_code,
                        EMPTY_CRC)
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode), tbr_percent, tbr_mins, id_code,
                        calculateCrcForSubFrame(app_packet))

    if (testing == True):
        hexdump.hexdump(app_packet)

    packet = build_DataPacket(comid=comid, nonce=nonce,
                              key=key,
                              channel=channel,
                              data=app_packet)
    return packet


def build_UpdateTBR(nonce=None, channel=None, comid=None, key=None, tbr_percent=None, tbr_mins=None, testing=False):
    s = getStructFromDefinition('UpdateTBR')

    if (not testing and not validate_tbr_parameters(tbr_percent=tbr_percent, tbr_mins=tbr_mins)):
        print "Validation failed for TBR parameters"
        return None

    service = 0x66
    id_code = 0x1F
    app_opcode = getAppCommandValueFromName(service, 'Update TBR')
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode), tbr_percent, tbr_mins, id_code,
                        EMPTY_CRC)
    app_packet = s.pack(PROTOCOL_VERSION, service, commandNumberToBytes(app_opcode), tbr_percent, tbr_mins, id_code,
                        calculateCrcForSubFrame(app_packet))

    if (testing == True):
        hexdump.hexdump(app_packet)

    packet = build_DataPacket(comid=comid, nonce=nonce,
                              key=key,
                              channel=channel,
                              data=app_packet)
    return packet


if __name__ == "__main__":
    print "Running app packet factory test parameters"
