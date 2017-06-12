## To install:

This is highly experimental and should only be used by researchers who know exactly what they are doing. By using any of this information or source code you accept all associated risks. If you are unsure then please do not continue.

If everything works then will be able to connect the handset and the data it sends over the rfcomm socket will be outputted as a hexdump

### Linux:

I used a Raspberry Pi 2 with Raspian jessie installed and *two* CSR 4.0 micro dongles. These are currently the best selling usb bluetooth dongles on amazon at approx 7 euros each. They identify as using the CSR8510 A10 chipset.

I think it should work on Debian jessie but the script relies on some defaults that are seen with the bluetooth subsystem. For example we already have a PNP service on handle 0x10000 that we can then use.

### Preparation:

Bluetooth needs to be set up to provide the features we need

Use your favorite editor to edit: `dbus-org.bluez.service`

    sudo nano /etc/systemd/system/dbus-org.bluez.service

Change the line which begins `ExecStart` to look like this:

    ExecStart=/usr/lib/bluetooth/bluetoothd --compat --experimental

Insert a bluetooth dongle which is fairly recent. A CSR chipset BT 4.x dongle should work. You probably need to restart the bluetooth service or reboot to ensure the new settings are being used.

#### Compiling joh-sdptool:

You need a patched version of sdptool to set uint16 attributes. I call this `joh-sdptool`

    sudo apt-get install -y glib2.0-dev libdbus-1-dev libical-dev libreadline-dev
    mkdir work
    cd work
    wget http://www.kernel.org/pub/linux/bluetooth/bluez-5.45.tar.xz
    tar -xJvf bluez-5.45.tar.xz
    cd bluez-5.45

Copy the `sdptool.patch` file in to the `bluez-5.45/tools` folder

    cd tools
    patch <sdptool.patch
    cd ..

Now to compile bluez, it is really only `sdptool` and `bdaddr` we are interested in though

    ./configure  --enable-experimental --enable-deprecated
    make

Once compiled install it somewhere

    sudo cp tools/sdptool /usr/local/bin/joh-sdptool

Check it works and your bluetooth is up and running

    joh-sdptool browse local

If you are using two bluetooth dongles and you somehow manage to get sold two with the same mac address (which happened to me) then you can change the mac address of one of them using eg:

    tools/bdaddr -i hciX 00:11:22:33:44:55

#### Python install:

Now make sure you have python 2.x installed

    sudo apt-get install -y python python-pip

Use pip to install: hexdump, logger, pybluez

    sudo pip install hexdump
    sudo pip install logger
    sudo pip install pybluez

#### Starting it up:

First you need to know the real mac address of your pump device. To get this, put it in to pairing mode and then try either

    hcitool scan

or

    hcitool inq

Until you can determine the mac address.

Then to start the script (replacing xx's with your actual mac address)

    sudo bash sight-proxy.sh xx:xx:xx:xx:xx:xx

The shell script will set up some parameters, prepare the sdp records how they should look and launch the python script to provide the local rfcomm socket

If everything worked during setup then you should see a line which says:

    Starting proxy
    Waiting on channel 1

And then below this you should see *exactly* this:

```
Sequence
	Attribute 0x0000 - ServiceRecordHandle
		UINT32 0x00010000
	Attribute 0x0001 - ServiceClassIDList
		Sequence
			UUID16 0x1200 - PnPInformation
	Attribute 0x0005 - BrowseGroupList
		Sequence
			UUID16 0x1002 - PublicBrowseGroup
	Attribute 0x0200
		UINT16 0x0103
	Attribute 0x0201
		UINT16 0x173a
	Attribute 0x0202
		UINT16 0x0052
	Attribute 0x0203
		UINT16 0x0100
	Attribute 0x0204
		Bool True
	Attribute 0x0205
		UINT16 0x0002
Service Search failed: Invalid argument
Sequence
	Attribute 0x0000 - ServiceRecordHandle
		UINT32 0x00010001
	Attribute 0x0001 - ServiceClassIDList
		Sequence
			UUID16 0x1101 - SerialPort
	Attribute 0x0004 - ProtocolDescriptorList
		Sequence
			Sequence
				UUID16 0x0100 - L2CAP
			Sequence
				UUID16 0x0003 - RFCOMM
				UINT8 0x01
	Attribute 0x0005 - BrowseGroupList
		Sequence
			UUID16 0x1002 - PublicBrowseGroup
	Attribute 0x0006 - LanguageBaseAttributeIDList
		Sequence
			UINT16 0x656e
			UINT16 0x006a
			UINT16 0x0100
	Attribute 0x0009 - BluetoothProfileDescriptorList
		Sequence
			Sequence
				UUID16 0x1101 - SerialPort
				UINT16 0x0100
	Attribute 0x0100
		String PUMP-MDL

```

Now you can take your handset, remove the current pairing and add a new device and select the Linux device and at that point you will start to see data appear in hexdump output! Good luck!

Logs will be stored in a created folder `logs` in the current directory.

### Limitations:

The scripts are very simple prototypes without any error checking, it either works straight off or some missing component will completely prevent it from working.

Its possible my patches to sdptool are too simplistic and only work on little endian, so will work on raspberry pi but not on a PC - this needs checking

I have only tested this in a multi-dongle configuration, it may work with just a single dongle but I thought two was more likely to succeed.


### To do:

Currently this is a proof of concept. Testing is needed to verify it works on different platforms other than the raspberry pi.







