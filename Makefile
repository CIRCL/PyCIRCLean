install:
	sudo apt-get update
	sudo apt-get -y p7zip-full p7zip-rar libxml2-dev libxslt1-dev
	pip install lxml exifread pillow olefile oletools python-magic
	pip install git+https://github.com/grierforensics/officedissector.git
 	wget https://didierstevens.com/files/software/pdfid_v0_2_1.zip
 	unzip pdfid_v0_2_1.zip
