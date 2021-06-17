FROM golang

WORKDIR /go/src/github.com/san-lab
RUN git clone https://github.com/san-lab/goavalon && cd /go/src/github.com/san-lab/goavalon && go build
ENV httpPort "8100"
WORKDIR /go/src/github.com/san-lab/goavalon
CMD ./goavalon -httpPort=$httpPort 
