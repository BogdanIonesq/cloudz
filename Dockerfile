FROM golang as build

WORKDIR /cloudz
COPY app .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build .

FROM alpine
COPY --from=build /cloudz/app /cloudz/app
CMD ["/cloudz/app"]