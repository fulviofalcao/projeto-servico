# Stage 1: build
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

# Stage 2: runtime
FROM openjdk:21-jdk-slim
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

COPY server_private.pem .
COPY server_public.pem .

EXPOSE 8888

ENTRYPOINT ["java", "-jar", "app.jar"]

