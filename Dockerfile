FROM ballerina/ballerina:2201.12.10

WORKDIR /app

# Copy the Ballerina project files
COPY Ballerina.toml .
COPY *.bal .
COPY modules ./modules

# Build the Ballerina application (will generate Dependencies.toml)
RUN bal build

# Copy resources after build (so they're available at runtime)
COPY resources ./resources

# Set the entrypoint to run the Ballerina JAR
ENTRYPOINT ["bal", "run", "target/bin/afm_ballerina.jar"]
