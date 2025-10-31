# Authentication Microservice Setup Documentation

## Overview
This document provides comprehensive documentation for setting up the Authentication microservice for the bancassurance system. The microservice is built using Spring Boot 3.5.7 with Java 21 and follows microservice architecture patterns with JWT-based authentication.

## Prerequisites
- Java 21 (OpenJDK)
- Maven 3.6+
- PostgreSQL 12+
- IDE (IntelliJ IDEA, Eclipse, or VS Code)
- Spring Initializr access

## Project Configuration

### Spring Initializr Setup

#### Basic Project Metadata
```
Project Type: Maven Project
Language: Java
Spring Boot Version: 3.5.7
Group ID: com.bancassurance
Artifact ID: authentication
Name: Authentication
Description: Microservice architecture for a bancassurance system's authentication module
Package Name: com.bancassurance.authentication
Packaging: jar
Java Version: 21
Configuration Format: YAML
```

#### Selected Dependencies

##### Core Framework Dependencies
- **Spring Web**: For building REST APIs and web applications
- **Spring Security**: For authentication and authorization mechanisms
- **Spring Data JPA**: For database operations and ORM functionality
- **PostgreSQL Driver**: Database connectivity for PostgreSQL
- **Spring Boot Actuator**: For monitoring and health checks

##### Microservice Dependencies
- **Eureka Discovery Client**: For service registration and discovery
- **Config Client**: For centralized configuration management
- **Cloud LoadBalancer**: For client-side load balancing

##### Utility Dependencies
- **Validation**: For input validation and constraint checking
- **Lombok**: For reducing boilerplate code

### Generated Project Structure
```
authentication/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── bancassurance/
│   │   │           └── authentication/
│   │   │               └── AuthenticationApplication.java
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── static/
│   │       └── templates/
│   └── test/
│       └── java/
│           └── com/
│               └── bancassurance/
│                   └── authentication/
│                       └── AuthenticationApplicationTests.java
├── target/
├── pom.xml
├── mvnw
├── mvnw.cmd
└── HELP.md
```

## Maven Configuration (pom.xml)

### Complete POM Configuration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>3.5.7</version>
		<relativePath/>
	</parent>
	<groupId>com.bancassurance</groupId>
	<artifactId>authentication</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>authentication</name>
	<description>Microservice architecture for a bancassurance system's authentication module</description>
	<properties>
		<java.version>21</java.version>
		<spring-cloud.version>2025.0.0</spring-cloud.version>
	</properties>
	<dependencies>
		<!-- Core Spring Boot Dependencies -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-actuator</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-validation</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		
		<!-- Spring Cloud Dependencies -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-config</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-loadbalancer</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
		</dependency>

		<!-- Database Dependencies -->
		<dependency>
			<groupId>org.postgresql</groupId>
			<artifactId>postgresql</artifactId>
			<scope>runtime</scope>
		</dependency>
		
		<!-- Utility Dependencies -->
		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<optional>true</optional>
		</dependency>
		
		<!-- Test Dependencies -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>
	
	<dependencyManagement>
		<dependencies>
			<dependency>
				<groupId>org.springframework.cloud</groupId>
				<artifactId>spring-cloud-dependencies</artifactId>
				<version>${spring-cloud.version}</version>
				<type>pom</type>
				<scope>import</scope>
			</dependency>
		</dependencies>
	</dependencyManagement>

	<build>
		<plugins>
			<plugin>
				<groupId>org.apache.maven.plugins</groupId>
				<artifactId>maven-compiler-plugin</artifactId>
				<configuration>
					<annotationProcessorPaths>
						<path>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</path>
					</annotationProcessorPaths>
				</configuration>
			</plugin>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<configuration>
					<excludes>
						<exclude>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</exclude>
					</excludes>
				</configuration>
			</plugin>
		</plugins>
	</build>
</project>
```

## Additional Dependencies Setup

### JWT Authentication Dependencies
After initial project generation, the following JWT dependencies were added to enable JSON Web Token functionality:

```xml
<!-- JWT Dependencies for Token-based Authentication -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```

### API Documentation Dependencies
```xml
<!-- SpringDoc OpenAPI for Swagger Documentation -->
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
    <version>2.2.0</version>
</dependency>
```

### Caching Dependencies
```xml
<!-- Caffeine Cache for Token Management -->
<dependency>
    <groupId>com.github.ben-manes.caffeine</groupId>
    <artifactId>caffeine</artifactId>
</dependency>
```

## Dependency Analysis

### Core Framework Dependencies Explanation

#### Spring Boot Starters
- **spring-boot-starter-web**: Provides embedded Tomcat server, Spring MVC, and RESTful web services capabilities
- **spring-boot-starter-security**: Includes Spring Security framework for authentication and authorization
- **spring-boot-starter-data-jpa**: Provides JPA implementation with Hibernate for database operations
- **spring-boot-starter-validation**: Bean validation with Hibernate Validator
- **spring-boot-starter-actuator**: Production-ready monitoring and management endpoints

#### Spring Cloud Dependencies
- **spring-cloud-starter-config**: Enables externalized configuration in distributed systems
- **spring-cloud-starter-netflix-eureka-client**: Service discovery client for registering with Eureka server
- **spring-cloud-starter-loadbalancer**: Client-side load balancing capabilities

#### Database and Persistence
- **postgresql**: PostgreSQL JDBC driver for database connectivity
- **spring-data-jpa**: Repository pattern implementation and query methods

#### JWT Authentication
- **jjwt-api**: JWT API for token creation and parsing
- **jjwt-impl**: JWT implementation library
- **jjwt-jackson**: JSON processing for JWT tokens

### Development and Utility Dependencies
- **lombok**: Reduces boilerplate code with annotations
- **springdoc-openapi**: Automatic API documentation generation
- **caffeine**: High-performance caching library

## Project Initialization Steps

### Step 1: Spring Initializr Configuration
1. Navigate to [Spring Initializr](https://start.spring.io/)
2. Configure project metadata as specified above
3. Select all required dependencies
4. Generate and download the project ZIP file

### Step 2: Project Import
1. Extract the downloaded ZIP file
2. Import the project into your preferred IDE
3. Wait for Maven to download all dependencies

### Step 3: Additional Dependencies
1. Open `pom.xml`
2. Add JWT, SpringDoc, and Caffeine dependencies
3. Refresh Maven dependencies

### Step 4: Project Structure Verification
Ensure the following structure is created:
```
src/main/java/com/bancassurance/authentication/
├── AuthenticationApplication.java (Main application class)
├── config/ (Configuration classes - to be created)
├── controllers/ (REST controllers - to be created)
├── models/ (Entity classes - to be created)
├── repositories/ (Data access layer - to be created)
├── services/ (Business logic layer - to be created)
└── security/ (Security configuration - to be created)
```

## Configuration Preparation

### Application Configuration Structure
The microservice will require the following configuration files:
- `application.yml`: Main application configuration
- Database connection settings
- JWT configuration properties
- Eureka client configuration
- Actuator endpoints configuration

### Planned Service Architecture
The authentication service will implement:
- **JWT-based authentication**: Stateless token authentication
- **Role-based authorization**: Dynamic role and permission management
- **Database authentication**: Local user credential storage
- **Active Directory integration**: Enterprise authentication support
- **Password management**: Reset and change functionality
- **User lifecycle management**: Registration, approval, and deactivation

## Next Steps
1. Database setup and schema creation
2. Entity model implementation
3. Repository layer development
4. Service layer implementation
5. Security configuration
6. REST API controller development
7. JWT service implementation
8. Integration testing

## Technology Stack Summary
- **Framework**: Spring Boot 3.5.7
- **Language**: Java 21
- **Build Tool**: Maven
- **Database**: PostgreSQL
- **Authentication**: JWT + Spring Security
- **Service Discovery**: Netflix Eureka
- **Configuration**: Spring Cloud Config
- **Documentation**: SpringDoc OpenAPI
- **Caching**: Caffeine
- **Architecture**: Microservice with REST APIs

This setup provides a solid foundation for building a secure, scalable authentication microservice that integrates seamlessly with the existing microservice ecosystem.