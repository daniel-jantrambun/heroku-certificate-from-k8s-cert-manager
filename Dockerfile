FROM golang:1.20

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /heroku-certificate-from-k8s-cert-manager

# Run
CMD ["/heroku-certificate-from-k8s-cert-manager"]