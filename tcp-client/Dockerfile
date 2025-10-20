FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

FROM openjdk:21-jdk-slim
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

COPY client_private.pem .
COPY client_public.pem .

ENV TCP_SERVER_ADDRESS=tcp-server
ENV TCP_SERVER_PORT=8888

ENTRYPOINT ["java", "-jar", "app.jar"]
