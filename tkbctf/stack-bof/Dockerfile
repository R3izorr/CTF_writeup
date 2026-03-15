FROM ubuntu:24.04@sha256:98ff7968124952e719a8a69bb3cccdd217f5fe758108ac4f21ad22e1df44d237 AS base
WORKDIR /app

COPY --chmod=555 ./stack-bof run

RUN echo "tkbctf{*** REDACTED ***}" > flag.txt
RUN mv flag.txt /flag-$(md5sum flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=300 JAIL_CPU=100 JAIL_MEM=10M
