# Image for the licence server.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /shipshape-server ./cmd/shipshape-server

FROM gcr.io/distroless/static-debian12
COPY --from=build /shipshape-server /shipshape-server
EXPOSE 8080
ENTRYPOINT ["/shipshape-server"]
