FROM ubuntu:14.04
MAINTAINER phonchi <steve2003121@gmail.com>
# Install required packages and remove the apt packages cache when done.

RUN apt-get update && apt-get install -y \
	git \
	python2.7 \
	python2.7-dev \
	python2.7-libs \
	python-numpy \
	python-scipy \
	python-pyside \
	python-configobj \
	python-setuptools \
	python-pip \
	zip \
	unzip \
    wget \
  && rm -rf /var/lib/apt/lists/*

RUN pip install pyqtgraph \
				pyusb

RUN mkdir /chipwhisperer				
RUN git clone https://github.com/phonchi/chipwhisperer.git
WORKDIR  "/chipwhisperer"
RUN git clone https://git.assembla.com/openadc.git
RUN chmod -R 755 /chipwhisperer
WORKDIR  "/chipwhisperer/software/"
RUN python setup.py develop
WORKDIR  "/chipwhisperer/openadc/controlsw/python/"
RUN python setup.py develop
WORKDIR "/"
RUN wget https://github.com/snmishra/ftd2xx/archive/master.zip
RUN unzip master.zip
WORKDIR "/ftd2xx-master/"
RUN python setup.py install
WORKDIR "/"
RUN wget http://www.ftdichip.com/Drivers/D2XX/Linux/libftd2xx-x86_64-1.3.6.tgz
RUN tar xvf libftd2xx-x86_64-1.3.6.tgz
WORKDIR "/release/build/"
RUN cp libftd2xx.* /usr/local/lib
RUN chmod 755 /usr/local/lib/libftd2xx.so.1.3.6
WORKDIR "/"

CMD ["/bin/bash"]
