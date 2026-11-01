# syntax=docker/dockerfile:1

# Build on the runner's own architecture and cross-compile for TARGETARCH, so arm64 images are not built under emulation.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build-base
ARG TARGETARCH
WORKDIR /src

COPY src/auth-gateway/AuthGateway.csproj src/auth-gateway/
RUN architecture="$TARGETARCH"; [ "$architecture" != "amd64" ] || architecture="x64"; \
    dotnet restore src/auth-gateway/AuthGateway.csproj \
        --runtime "linux-$architecture" \
        --property:PublishReadyToRun=true

COPY src/auth-gateway/ src/auth-gateway/

FROM build-base AS jit-build
RUN architecture="$TARGETARCH"; [ "$architecture" != "amd64" ] || architecture="x64"; \
    dotnet publish src/auth-gateway/AuthGateway.csproj \
        --configuration Release \
        --runtime "linux-$architecture" \
        --self-contained false \
        --no-restore \
        --property:PublishReadyToRun=true \
        --output /app/jit

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS jit
LABEL org.opencontainers.image.title="auth-gateway" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Microsoft Entra authentication gateway: signs people and programs in and forwards requests with a short-lived signed identity assertion."
WORKDIR /app
ENV DOTNET_ENVIRONMENT=Production \
    Kestrel__Endpoints__Http__Url=http://0.0.0.0:8080 \
    Kestrel__Endpoints__Http__Protocols=Http1 \
    Kestrel__Endpoints__Grpc__Url=http://0.0.0.0:8082 \
    Kestrel__Endpoints__Grpc__Protocols=Http2
EXPOSE 8080 8082
COPY --from=jit-build --chown=app:app /app/jit/ ./
USER app
ENTRYPOINT ["dotnet", "AuthGateway.dll"]

# The unqualified build output is the JIT/ReadyToRun image.
FROM jit AS final
