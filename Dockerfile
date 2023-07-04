FROM ubuntu:22.04

RUN apt-get update && apt install lsb-release net-tools vim openssh-server sudo -y
RUN apt install git build-essential libpam0g-dev libcurl4-openssl-dev  libqrencode-dev libssl-dev -y

RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 test

ARG TOKEN_URL
ARG DEVICE_URL
ARG CLIENT_ID

RUN mkdir /lib/security
RUN sed -i 's|@include common-auth|#@include common-auth\nauth required deviceflow.so token_url='"$TOKEN_URL"' device_url='"$DEVICE_URL"' client_id='"$CLIENT_ID"'|' /etc/pam.d/sshd
RUN sed -i 's|@include common-password|#@include common-password|'  /etc/pam.d/sshd
RUN sed -i 's|KbdInteractiveAuthentication no|KbdInteractiveAuthentication yes|' /etc/ssh/sshd_config

WORKDIR /tmp/workdir
ADD ./ /tmp/workdir

RUN gcc -fPIC -c deviceflow.c qr.c
RUN sudo ld -x --shared -o /lib/security/deviceflow.so deviceflow.o qr.o -lm -lqrencode -lcurl -lssl -lcrypto

RUN  echo 'test:1' | chpasswd

RUN service ssh start

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]