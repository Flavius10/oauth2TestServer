# oauth2TestServer

OAuth2TestServer is a lightweight Authorization Server implemented with Spring Security for testing OAuth 2.0 flows.
It allows developers to simulate authentication and authorization scenarios and secure APIs without relying on a production identity provider.

---

Features
- Implements OAuth 2.0 Authorization Code Flow
- Issues JWT tokens with custom role claims
- Supports role-based authorization for API endpoints
- Configurable clients and users for testing purposes
- Can be used in combination with other applications (e.g., BestInsuranceApi)

---

Requirements
- JDK 17 (or higher)
- Maven Wrapper (mvnw)
- (Optional) Docker for containerized execution

---

Running the project

Build the project using Maven:

./mvnw clean package -DskipTests

This generates a .war file in the target directory.

Note: To use OAuth2TestServer with BestInsuranceApi, copy the generated .war file manually to the appropriate directory of the BestInsuranceApi project. This server provides the OAuth2 security for the API.

---

Skills Learned / Project Conclusions

By completing this project, you will learn how to:

- Implement an authorization server with Spring Security, issuing JWT tokens with custom claims for roles
- Secure an existing API with role-based authorization
- Implement a resource server with Spring Security
- Configure SwaggerUI to make authenticated requests
- Write unit tests considering security configurations

---

Code Structure
- src/main/java – contains the Spring Boot application and configuration for OAuth2
- src/test – unit and integration tests
- target – generated .war file after building the project

---

Contributing

Contributions are welcome. Please open an issue to discuss major changes before submitting a pull request.

---

Contact

Maintained by OAuth2TestServer team.
Use GitHub issues for questions, suggestions, or reporting bugs.

