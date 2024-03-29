# auth-server
This is a server for token based authentication to be used by web applications. 

Endpoints:
1) Register
2) Approve - Once a registration is submitted, it must be approved by an existing administrator.
3) Request password reset- The password reset link will be emailed to the user (forgotten password) or to an approved registration (setup password)
3) Reset Password
4) Login 
5) Logout


For testing, flask mail simulator must be running: 
```python -m smtpd -n -c DebuggingServer localhost:8025```

Kill process on port: 
kill $(lsof -t -i :5000)

1) Setup
Install docker
Install postgres
```brew install postgres```
Inside virtual environment, install dependencies
```pip install -r requirements```

Create docker container running the database:
```docker run -d --name token_auth_server -e POSTGRES_DB=flask_jwt_auth_dev -e POSTGRES_PASSWORD=ONLIN3-ex4m -p 5432:5432 postgres```

