# springboot-springsecurity-jwt
Authentication management with Spring Boot, Spring Security and JWT
### Authentication Diagram

<a href='https://svgshare.com/s/UFw' ><img src='https://svgshare.com/i/UFw.svg' title='jwtspring' /></a>

### Endpoints
| Route | HTTP Verb	 | POST body	 | Description	 |
| --- | --- | --- | --- |
| /authenticate | `POST` | {'name':'halis', 'surname':'123'} | if user is authenticated, return token  |
| /hello | `GET` |{'Authorization' : 'Bearer xxxxxx'} | Return hello world  |
