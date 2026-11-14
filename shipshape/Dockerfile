# Image for the GitHub Action (the CLI).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /shipshape ./cmd/shipshape

# distroless/static ships CA certificates, needed for HTTPS calls to the
# licence server and the GitHub API.
FROM gcr.io/distroless/static-debian12
COPY --from=build /shipshape /shipshape
ENTRYPOINT ["/shipshape"]
