import hexdump
from packet_factory import *

DIRTY_CLIENT = [
    '20 00 E8 F0 0F', '20 00 E8 F0 33', '20 00 E8 F0 55',
    #    '20 00 CD F3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', # binding pc
    '20 00 CD F3 34 38 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    # device 481 bind
    '20 00 F7 F0 33 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    '20 00 F7 F0 0F 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    '20 33 56 1E 94 8A',
    '20 0F D8 2E',

    '20 00 D2 F3 55 02 00', None,  # request challenge config write
    '20 00 D2 F3 66 01 00', None,  # request challenge insulin

    None
]

DIRTY_CLIENT_RECONNECT = [
    '20 00 0B F0 00 00 08 01 00 19 60 00',  # reconnect request
    '20 00 E8 F0 55',  # version of config service
    '20 00 D2 F3 55 02 00', None,  # request challenge config write
    '20 00 D2 F3 66 01 00', None,  # request challenge insulin
    None
]

DIRTY_CLIENT_RECONNECT_ORIGINAL = [
    "20 00 0B F0 00 00 08 01 00 19 60 00",  # reconnect request
    None
]

DIRTY_CLIENT_RESEARCH = [
    '20 00 E8 F0 55',
]

DIRTY_PUMP = {

    # get version
    '20 00 E8 F0 0F': '20 00 E8 F0 00 00 01 00',  # status reader
    '20 00 E8 F0 66': '20 00 E8 F0 00 00 01 00',  # insulin
    '20 00 E8 F0 33': '20 00 E8 F0 00 00 02 00',  # config reader
    '20 00 E8 F0 55': '20 00 E8 F0 00 00 02 00',  # config writer
    '20 00 E8 F0 3C': '20 00 E8 F0 00 00 02 00',  # unknown 3c

    '20 00 0B F0 00 00 08 01 00 19 60 00': '20 00 0B F0 00 00 00 00 00 00 00 00 00 00',  # app reconnect request
    '20 00 0B F0 2E 99 E8 00 00 19 60 00': '20 00 0B F0 00 00 00 00 00 00 00 00 00 00',  # handset reconnect
    '20 00 0B F0 00 00 E8 00 00 19 60 00': '20 00 0B F0 00 00 00 00 00 00 00 00 00 00',  # another handset reconnect

    # binding
    '20 00 CD F3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00': '20 00 CD F3 00 00 38 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    # null bind
    '20 00 CD F3 34 38 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00': '20 00 CD F3 00 00 38 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    # device 481 bind (mgdl)
    '20 00 CD F3 34 38 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00': '20 00 CD F3 00 00 38 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
    # device 482 bind (mmol)

    # activate services
    '20 00 F7 F0 33 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00': '20 00 F7 F0 00 00 33 02 00',
    '20 00 F7 F0 3C 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00': '20 00 F7 F0 00 00 3C 02 00',
    '20 00 F7 F0 0F 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00': '20 00 F7 F0 00 00 0F 01 00',

    # handset connect
    '20 00 41 F5': '20 00 41 F5 00 00 B4 00 00 00 00 00 B4 00 00 00 00 00 B4 00 00 00 00 00 B4 00 00 00 00 00 B4 00 00 00 00 00',
    # unknown!!!

    '20 0F AF A4': '20 0F AF A4 00 00 00 0E  2F FF FE 9E 61 E9',  # UNKNOWN!
    # reading

    '20 33 56 1E 94 8A': '20 33 56 1E 00 00 94 8A 73 1D 33 00 36 00 30 00 31 00 37 00 39 00 38 00 36 00 00 00 00 00 70 B8 15 00 30 00 31 00 2E 00 30 00 36 00 2E 00 32 00 30 00 31 00 35 00 00 00 00 00 94 5F',
    #  identity

    # '20 0F D8 2E': "20 0F D8 2E 00 00 56 32 2E 30 30 2E 30 30 34 00 00 00 00 00 56 32 2E 30 30 2E 30 32 33 00 00 00 56 32 2E 30 30 2E 30 32 30 00 00 00 56 32 2E 30 32 32 00 00 00 00 00 00 76 33 2E 30 30 2E 30 00 00 00 00 00 56 31 2E 30 34 00 00 00 00 00 00 00 2A 00 10 00 2E 00 05 00",
    # versions de
    '20 0F D8 2E': "20 0F D8 2E 00 00 56 31 2E 30 37 2E 30 32 00 00 00 00 00 00 56 31 2E 30 37 2E 30 31 39 00 00 00 56 31 2E 30 37 2E 30 31 37 00 00 00 56 32 2E 30 32 31 00 00 00 00 00 00 76 32 2E 33 36 2E 31 00 00 00 00 00 56 31 2E 30 32 00 00 00 00 00 00 00 27 00 0F 00 2E 00 05 00",
    # versions uk

    '20 55 56 1E 17 EB': '20 55 56 1E 00 00 17 EB  73 1D 05 00 C1 41',  # read bolus factory min 0.05
    '20 55 56 1E EB EB': '20 55 56 1E 00 00 EB EB  73 1D 02 00 9E FD',  # basal rate minimum 0.02
    '20 55 56 1E 06 A1': '20 55 56 1E 00 00 06 A1  73 1D 88 13 7E 94',  # bolus amount limit 50.00
    '20 55 56 1E E5 A1': '20 55 56 1E 00 00 E5 A1  73 1D C8 00 C4 09 07 66',  # infusion set limit ?
    '20 55 56 1E FA A1': '20 55 56 1E 00 00 FA A1  73 1D 10 27 13 C5',  # cartridge warning max limit 100u

    '20 66 6C 1D': '20 66 6C 1D 00 00',  # insulin unknown

    '20 55 56 1E 1F 00': '20 55 56 1E 00 00 1F 00  1F 00 C4 09 1A 36',  # max bolus setting 25u
    '20 55 56 1E 39 18': '20 55 56 1E 00 00 39 18  1F 00 B4 00 E5 28',  # bolus time lag enabled
    '20 55 56 1E 37 52': '20 55 56 1E 00 00 37 52  1F 00 32 00 4B 00 0D E0',  # bolus steps

    '20 0F FC 00': '20 0F FC 00 00 00 E3 00 49 33',  # bolus reminder?

    '20 00 31 F3': '20 00 31 F3 00 00',  # shut them all down
    '20 00 14 F0 03 60': '20 00 14 F0 00 00'  # disconnect
}


def getDirtyPumpReply(decrypted):
    lookup = hexdump.dump(decrypted)
    if DIRTY_PUMP.has_key(lookup):
        return DIRTY_PUMP[lookup]
    return None


### self test

if __name__ == "__main__":
    print "Running dirty emulator test parameters"