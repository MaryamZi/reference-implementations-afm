# Build stage (discarded after build)
FROM ballerina/ballerina:2201.12.10 AS builder

USER root

WORKDIR /app

COPY Ballerina.toml .
COPY *.bal .
COPY modules ./modules

RUN bal build

# Runtime stage - slim JRE only
FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=builder /app/target/bin/afm_ballerina.jar ./
COPY resources ./resources

ENTRYPOINT ["java", "-jar", "afm_ballerina.jar"]
