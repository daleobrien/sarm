FROM arm64v8/alpine:latest AS builder

RUN apk add --no-cache gcc binutils make

WORKDIR /app
COPY certs certs
COPY www www
COPY embed_www.sh .
COPY build_err_pages.sh .
COPY src src
COPY Makefile .

RUN make
