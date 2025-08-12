# Keycloak Spring Boot Integration Project

## What Does It Do?

This project secures Spring Boot REST APIs using Keycloak. Users first obtain a JWT token from Keycloak, then use this token to make API requests.

## How Does It Work?

1. **Keycloak** runs as the identity authentication server (port 8080)
2. **Spring Boot** application provides REST API (port 8881)
3. User logs into Keycloak with username/password
4. Keycloak returns a JWT token
5. User uses this token in API requests
6. Spring Boot validates the token and checks roles

## Key Features

- **JWT Token Validation**: Automatically validates tokens from Keycloak
- **Role-Based Authorization**: Each endpoint can require different roles
- **Stateless**: No session stored on server, each request is validated with token

## Example Scenario

- User with `client_user` role → Can access `/api/v1/auth/hi-user` endpoint
- User with `client_admin` role → Can access `/api/v1/auth/hi-admin` endpoint
- User with wrong role → Gets 403 Forbidden error
- Request without token → Gets 401 Unauthorized error

## Why Use It?

- Centralized user management
- Ideal for microservice architecture
- Separates security code from business logic
- Production-ready authentication/authorization solution
