FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/xso-idp ./apps/xso-idp/cmd/xso-idp

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/xso-idp /xso-idp
EXPOSE 8080
ENTRYPOINT ["/xso-idp"]
