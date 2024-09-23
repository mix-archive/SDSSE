FROM ubuntu:16.04
ENV USER=deploy
ENV PASSWD=deploy
ENV WORKDIR=SDSSE
ENV TZ=Australia/Melbourne

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update \
    && apt install -y ssh openssh-server build-essential \
      gcc g++ gdb gdbserver \
      rsync \
      sudo git \
      flex bison \
      libgmp-dev \
    && apt clean

RUN useradd -m ${USER} && yes ${PASSWD} | passwd ${USER}

RUN echo ${USER}' ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN chmod 644 /etc/sudoers

CMD ["/usr/sbin/sshd", "-D"]

USER ${USER}
RUN mkdir -p /home/${USER}/${WORKDIR}/
WORKDIR /home/${USER}/${WORKDIR}/
ENV LC_ALL C.UTF-8

RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar zxf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure \
    && make \
    && sudo make install && cd .. \
    && wget https://www.openssl.org/source/openssl-1.1.0h.tar.gz \
    && tar -zxf openssl-1.1.0h.tar.gz && cd openssl-1.1.0h \
    && ./config \
    && make \
    && sudo make install && cd ..\
    && wget https://github.com/Kitware/CMake/archive/refs/tags/v3.17.0.tar.gz \
    && tar -zxf v3.17.0.tar.gz && cd CMake-3.17.0 \
    && ./bootstrap && make && sudo make install