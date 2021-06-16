FROM golang

WORKDIR /go/src/github.com/san-lab
RUN git clone https://github.com/san-lab/goavalon
RUN go get golang.org/x/crypto/ed25519
WORKDIR /go/src/github.com/san-lab/goavalon
RUN go build
ENV httpPort "8100"
CMD ./goavalon -httpPort=$httpPort 
