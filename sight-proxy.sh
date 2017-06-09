#!/bin/bash
echo
echo "Designed to run on a raspberry pi running raspbian jessie"
echo
echo "This needs the modified version of sdptool which supports UINT16 attribute setting"
echo

# you can use bluez tools "bdaddr" cmd to change your bluetooth dongle mac address
# tools/bdaddr -i hci0 A0:E6:F8:FE:C7:5C


real_pump_mac="$1"
if [ "$real_pump_mac" = "" ]
then
echo "You need to call this script with the parameter of your real pump mac, eg:"
echo "sudo bash $0 11:22:33:44:55:66"
echo
echo "To determine the mac address, set the pump in to pairing mode and issue the command"
echo "hcitool scan   or   hcitool inq"
echo
exit
fi


echo "Shutting down any previous running"
pkill -f "sight-proxy.py"
pkill -f "sight-pairing-agent.py"

echo "Gathering information about dongles"

dongles=`hciconfig | grep 'hci[0-9]' | head -2 | sort | cut -f1 -d':'`
numdong=`echo "$dongles" | wc -l | tr -dc '0-9'`
echo
echo "You appear to have $numdong dongles"

if [ "$numdong" = "0" ]
then
echo "ERROR no dongles detected!"
exit 5
fi


for element in $dongles
do
if [ "$indongle" = "" ]
then
indongle="$element"
inmac=`hciconfig "$indongle" | grep 'BD Address' | tr -d '\t' | cut -f3 -d' ' | tr -dc '0-9A-F:'`
echo " Inbound dongle set to: $indongle ($inmac)"
else
outdongle="$element"
outmac=`hciconfig "$outdongle" | grep 'BD Address' | tr -d '\t' | cut -f3 -d' ' | tr -dc '0-9A-F:'`
echo "Outbound dongle set to: $outdongle ($outmac)"
fi
done
if [ "$outdongle" = "" ]
then
outdongle="$indongle"
outmac=`hciconfig "$outdongle" | grep 'BD Address' | tr -d '\t' | cut -f3 -d' ' | tr -dc '0-9A-F:'`
echo "Outbound dongle set to: $outdongle ($outmac) (single)"
fi



handle="0x10000"
#device="$indongle"

echo
echo "Assuming PNP service: $handle"
echo

# 0y means uint16
joh-sdptool -i $indongle setattr "$handle" 0x0200 0y0103
joh-sdptool -i $indongle setattr "$handle" 0x0201 0y173A
joh-sdptool -i $indongle setattr "$handle" 0x0202 0y0052
joh-sdptool -i $indongle setattr "$handle" 0x0203 0y0100
#joh-sdptool -i $indongle setattr "$handle" 0x0204 true
joh-sdptool -i $indongle setattr "$handle" 0x0205 0y0002

joh-sdptool -i $indongle setattr "$handle" 0x0009 0z0000 # delete

# get rid of everything else
for hand in 0x10001 0x10002 0x10003 0x10004 0x10005 0x10006 0x10007 0x10008 0x10009 0x1000a 0x1000b
do
#echo "Disabling not-needed services $hand"
joh-sdptool -i $indongle >/dev/null del "$hand"
done

echo
echo "Starting proxy"
# actually the pairing agent seems to break things
#python sight-pairing-agent.py &
python sight-proxy.py "$real_pump_mac" "$outmac" $2 &
sleep 4

echo
rfcomm="0x10001"
echo "Assuming RFComm on $rfcomm"

joh-sdptool -i $indongle setseq "$rfcomm" 0x0006 0y656e 0y006a 0y0100

# make discoverable
echo "Making discoverable"
sudo hciconfig "$indongle" class 0x000900
sudo hciconfig "$indongle" name "PUMP32014627"
sudo hciconfig "$indongle" piscan

if [ "$outdongle" != "$indongle" ]
then
echo "Also configuring outbound dongle"
sudo hciconfig "outdongle" class 0x000910
sudo hciconfig "$outdongle" name "METER32014627"
sudo hciconfig "$outdongle" piscan
fi

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


