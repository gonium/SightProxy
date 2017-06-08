#!/bin/bash
echo
echo "Designed to run on a raspberry pi running raspbian jessie"
echo
echo "This needs the modified version of sdptool which supports UINT16 attribute setting"
echo

# you can use bluez tools "bdaddr" cmd to change your bluetooth dongle mac address
# tools/bdaddr -i hci0 A0:E6:F8:FE:C7:5C

echo "Shutting down any previous running"
pkill -f "sight-proxy.py"

handle="0x10000"
device="hci0"

echo
echo "Assuming device: $device"
echo "Assuming PNP service: $handle"
echo

# 0y means uint16
joh-sdptool setattr "$handle" 0x0200 0y0103
joh-sdptool setattr "$handle" 0x0201 0y173A
joh-sdptool setattr "$handle" 0x0202 0y0052
joh-sdptool setattr "$handle" 0x0203 0y0100
#joh-sdptool setattr "$handle" 0x0204 true
joh-sdptool setattr "$handle" 0x0205 0y0002

joh-sdptool setattr "$handle" 0x0009 0z0000 # delete

# get rid of everything else
for hand in 0x10001 0x10002 0x10003 0x10004 0x10005 0x10006 0x10007 0x10008 0x10009 0x1000a 0x1000b
do
echo "Disabling not-needed services $hand"
joh-sdptool 2>/dev/null del "$hand"
done

echo
echo "Starting proxy"
python sight-proxy.py &
sleep 4

echo
rfcomm="0x10001"
echo "Assuming RFComm on $rfcomm"

joh-sdptool setseq "$rfcomm" 0x0006 0y656e 0y006a 0y0100

# make discoverable
echo "Making discoverable"
sudo hciconfig "$device" class 0x000900
sudo hciconfig "$device" name "PUMP32014627"
sudo hciconfig "$device" piscan
echo

# does this work?
#dbus-send --system --dest=org.bluez /org/bluez/hci0 org.bluez.Adapter.SetMode string:discoverable

joh-sdptool browse --raw local


echo
echo "Keypress to terminate"
read x
echo
# actually we dont really shut anything down yet
echo "SHUTDOWN"
echo


