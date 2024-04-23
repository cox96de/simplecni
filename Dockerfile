FROM golang:1.20 as builder
ADD . /src
WORKDIR /src
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go build -o simplecni ./cmd/simplecni
FROM debian
COPY --from=builder /src/simplecni /
RUN apt-get update && apt-get install -y iptables && apt-get clean && rm -rf /var/lib/apt/lists/* /var/log/dpkg.log /var/log/apt/*
ENTRYPOINT /simplecni