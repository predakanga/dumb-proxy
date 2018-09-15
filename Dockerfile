FROM golang:1.11

WORKDIR /build
COPY . .

RUN go get .

CMD ["dumb-proxy"]
