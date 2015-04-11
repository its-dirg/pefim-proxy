FROM ubuntu:14.04

MAINTAINER DIRG, dirg@umu.se

VOLUME ["/opt/pefim-proxy"]

ADD start.sh /start.sh
ADD requirements.txt /opt/pefimproxy/requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    python-dev \
    libffi-dev \
    python-openssl \
    python-pip \
    xmlsec1 \
    libffi-dev \
    libssl-dev \
    ntp
apt-get clean
rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip
RUN pip install -r /opt/pefimproxy/requirements.txt && \
    pip install git+https://github.com/its-dirg/pefim-proxy.git@develop
#    pip install git+https://github.com/its-dirg/pefim-proxy.git#egg=pefim-proxy

WORKDIR /

#EXPOSE 8999

CMD ["bash", "/start.sh"]