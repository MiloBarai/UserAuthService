# User Authentication Service
## Functionalities
### Signup
Signup with username, password & email.

Sends a verification email on success.

### Validate User
Simply validates user with provided token sent in mail.

### Login
Login with username & password, will provide a JWT token on success.

Validates user not archived and enabled.

### Refresh Token
Refreshes an expired token using the provided expiery refresh time as a limit for time passed.

## To be added
* Resend verification email, if expired.
* Reset password using email.
* Change password with existing password
* Change user information
* Proper error handling for custom exceptions.
* Login traceability.
* Unit tests
* Logs

## Getting Started

### Required Setup in application properties
* Mysql database
* SMTP mail service (Example provided using Gmail)
* JWT Secret

### Building
* run mvnw.cmd
