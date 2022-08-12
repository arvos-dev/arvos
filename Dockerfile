FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt -y upgrade && apt -y install python3.9 python3-pip bcc python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

COPY requirements.txt /requirements.txt

RUN pip3 install -r requirements.txt && mkdir -p /stacks

COPY arvos-poc.py /arvos-poc.py
COPY arthas.py /arthas.py
COPY parsexml.py /parsexml.py
COPY arvos_vfs_java.json /arvos_vfs_java.json

RUN chmod +x arvos-poc.py && chmod 755 arvos-poc.py

ENTRYPOINT ["./arvos-poc.py"]
