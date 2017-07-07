#!/bin/bash

# To install python script filecheck.py
# Tested on Raspbian Jessie 


function installDependencies {
	apt-get update
	apt-get -y install autoconf libtool python-lxml p7zip-full
	apt-get -y install p7zip-full p7zip-rar libxml2-dev libxslt1-dev
	pip3 install lxml oletools olefile exifread pillow python-magic
	pip3 install git+https://github.com/Rafiot/officedissector.git

	wget https://didierstevens.com/files/software/pdfid_v0_2_1.zip
	unzip pdfid_v0_2_1.zip

}

function setupPyCIRCLean {
	git clone https://github.com/CIRCL/PyCIRCLean
	./PyCIRCLean/setup.py
}

function installClam {
	apt-get install -y clamav
	cd usr/local/etc/

	tail -n +10 clamd.conf.sample > clamd.conf
	sed -i -e 's/#LocalSocket/LocalSocket/g' clamd.conf
	sed -i -e 's/#DatabaseDirectory/DatabaseDirectory/g' clamd.conf

	tail -n +10 freshclam.conf.sample > freshclam.conf
	sed -i -e 's/#DatabaseDirectory/DatabaseDirectory/g' freshclam.conf
}

function test {
	mkdir source
	mkdir dest
	cp -fr PyCirclean/slides/PyCIRCLean source/.
	sudo python3 PyCIRCLean/bin/filecheck.py -s source -d dest
	echo Results of the test : 
	ls dest/
	sudo rm -rf dest/
	sudo rm -rf source/
}


cd ~/Documents
mkdir CIRCLPy
cd CIRCLPy

sudo su

installDependencies
installClam
setupPyCIRCLean

exit
test








