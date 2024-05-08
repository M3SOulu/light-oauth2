# light-docker
Configured ELK stack to run with OAuth2 MySQL. Run with:

```
docker compose -f docker-compose-oauth2-mysql.yml up
```

Kibana available at http://localhost:5601/

For other dockerfiles and more documentation, see original repo: https://github.com/networknt/light-docker

# light-oauth2 services, endpoints and response codes TODO list

- [x] `oauth2-service` *handle service database*
    - [x] `/oauth2/service@post` *register new service*
         - [x] 200 *correct*
         - [x] 404 *user not found*
    - [x] `/oauth2/service@put` *update existing service*
         - [x] 200 *correct*
         - [x] 404 *user not found*
         - [x] 404 *`serviceId` not found*
    - [x] `/oauth2/service@get` *get services from database*
        - [x] 200 *correct*
        - [x] 400 *`page` parameter missing*
    - [x] `/oauth2/service{serviceId}@delete` *delete a service*
         - [x] 200 *correct*
         - [x] 404 *`serviceId` not found*
    - [x] `/oauth2/service{serviceId}@get` *get a service from database*
         - [x] 200 *correct*
         - [x] 404 *`serviceId` not found*
    - [ ] ~~`/oauth2/service/{serviceId}/endpoint@post` *add endpoints to service*~~
         - [ ] ~~200 *correct*~~
         - [ ] ~~404 *`serviceId` not found*~~
    - [ ] ~~`/oauth2/service/{serviceId}/endpoint@delete` *delete endpoints of a service*~~
         - [ ] ~~200 *correct*~~
         - [ ] ~~404 *`serviceId` not found*~~
    - [ ]  ~~`/oauth2/service/{serviceId}/endpoint@get` *get endpoints of a service*~~
         - [ ] ~~200 *correct*~~
         - [ ] ~~404 *`serviceId` not found*~~
- [ ] `oauth2-client` *handle client database*
    - [x] `/oauth2/client@post` *register new client*
        - [x] 200 *correct*
        - [x] 400 *`clientId` already exists*
        - [x] 400 *`clientType` has illegal value*
        - [x] 400 *`clientProfile` has illegal value*
        - [x] 404 *user not found*
    - [x] `/oauth2/client@put` *update existing client*
        - [x] 200 *correct*
        - [x] 404 *`clientId` not found*
        - [x] 400 *`clientType` has illegal value*
        - [x] 400 *`clientProfile` has illegal value*
        - [x] 404 *user not found*
    - [x] `/oauth2/client@get` *get clients from database*
         - [x] 200 *correct*
         - [x] 400 *`page` parameter missing*
    - [x] `/oauth2/client/{clientId}@get` *get a client from database*
         - [x] 200 *correct*
         - [x] 404 *`serviceId` not found*
    - [x] `/oauth2/client/{clientId}@delete` *delete a client from database*
         - [x] 200 *correct*
         - [x] 404 *`serviceId` not found*
    - [ ] ~~`/oauth2/client/{clientId}/service/{serviceId}@post` *link an endpoint to a client*~~
         - [ ] ~~200 *correct*~~
         - [ ] ~~404 *`clientId` not found*~~
         - [ ] ~~404 *`serviceId` not found*~~
    - [ ] ~~`/oauth2/client/{clientId}/service/{serviceId}@delete` *delete linked endpoints of a client*~~
         - [ ] ~~200 *correct*~~
         - [ ] ~~404 *`clientId` not found*~~
         - [ ] ~~404 *`serviceId` not found*~~
    - [ ]  ~~`/oauth2/client/{clientId}/service/{serviceId}@get` *get endpoints linked to a client*~~
         - [ ] ~~200 *correct*~~
         - [ ] ~~404 *`clientId` not found*~~
         - [ ] ~~404 *`serviceId` not found*~~
    - [ ] ~~`/oauth2/client/{clientId}/service@get` *get all endpoints linked to a client*~~
        - [ ] ~~200 *correct*~~
        - [ ] ~~404 *`clientId` not found*~~
    - [ ] ~~`/oauth2/client/{clientId}/service@delete` *delete all endpoints linked to a client*~~
        - [ ] ~~200 *correct*~~
        - [ ] ~~404 *`clientId` not found*~~
- [x] `oauth2-user` *handle user database*
    - [x] `/oauth2/user@post` *create new user*
        - [x] 200 *correct*
        - [x] 400 *`userId` exists*
        - [x] 400 *email exists*
        - [x] 400 *password confirmation failed*
        - [x] 400 *password empty*
    - [x] `/oauth2/user@put` *update user*
        - [x] 200 *correct*
        - [x] 404 *user not found*
    - [x] `/oauth2/user@get` *get all users*
        - [x] 200 *correct*
        - [x] 400 *`page` parameter missing*
    - [x] `/oauth2/user/{userId}@get` *get a user*
        - [x] 200 *correct*
        - [x] 404 *user not found*
    - [x] `/oauth2/user/{userId}@delete` *delete a user*
        - [x] 200 *correct*
        - [x] 404 *user not found*
    - [x] `/oauth2/password/{userId}@post` *update password*
        - [x] 200 *correct*
        - [x] 404 *user not found*
        - [x] 401 *incorrect password*
        - [x] 400 *password confirmation failed*
- [ ] `oauth2-code` *authorization code flow*
  - [ ] `oauth2/code@get` *get authorization code*
    - [x] 302 *redirect with authorization code*
    - [ ] 401 *incorrect password*
    - [ ] 400 *`response_type` missing*
    - [ ] 400 *`client_id` missing*
    - [ ] 400 *`response_type` does not equal `code`*
    - [ ] 404 *`clientId` not found*
    - [ ] 400 *`PKCE`: invalid code challenge method*
    - [ ] 400 *`PKCE`: code challenge too short*
    - [ ] 400 *`PKCE`: code challenge too long*
    - [ ] 400 *`PKCE`: code challenge invalid format*
  - [ ] `oauth2/code@post` ?? *same as `get` but credentials are posted?*
- [ ] `oauth2-token` *access token*
  - [ ] `oauth2/token@post` *exchange authorization code for access token*
    - [x] 200 *correct, token issued*
    - [ ] 400 *unable to parse `x-www-form-urlencoded` form'
    - [x] 400 *illegal value for grant type*
    - [ ] 400 *authorization header missing*
    - [ ] 404 *`clientId` not found*
    - [ ] 401 *wrong `client_secret`*
    - [ ] 401 *authorization form cannot be decoded*
    - [ ] 401 *basic authorization header missing (bearer token is passed)* 
    - [ ] 400 *`PKCE`: code verifier too short*
    - [ ] 400 *`PKCE`: code verifier too long*
    - [ ] 400 *`PKCE`: code verifier invalid format*
    - [ ] 400 *`PKCE`: code verifier missing*
    - [ ] 400 *`PKCE`: verification failed*
- [ ] `oauth2-refresh-token` *manage refresh tokens*
  - [ ] `oauth2/refresh_token@get` *get all refresh tokens*
    - [ ] 200 *correct*
    - [ ] 400 *`page` parameter missing*
  - [ ] `oauth2/refresh_token/{refreshToken}@get` *get particular `refresh_token` info*
    - [ ] 200 *correct*
    - [ ] 404 *refresh token not found*
    - [ ] 400 *invalid refresh token*
  - [ ] `oauth2/refresh_token/{refreshToken}@delete` *delete `refresh_token`*
      - [ ] 200 *correct*
      - [ ] 404 *refresh token not found*
      - [ ] 400 *invalid refresh token*
- [ ] `oauth2-key` *encryption key exchange*
    - [ ] `oauth2/key/{keyId}@get` *get public key for JWT verification*
      - [ ] 200 *correct*
      - [ ] 401 *missing authorization with client credentials*
      - [ ] 401 *wrong client secret*
      - [ ] 404 *`clientId` not found*
      - [ ] 500 *`keyId `not found on server*

# Pipelines to implement

- [ ] OAuth2 flows
  - [x] Client credentials flow
  - [x] Authorization code flow
  - [x] Authorization code flow PKCE
  - [ ] Resource owner password flow
  - [ ] Refresh token flow
- [ ] Scope management
  - [ ] Linking endpoints to clients
  - [ ] Scope parameter in code/token requests
- [ ] Different values of
  - [ ] Service type
  - [ ] Client type
  - [ ] Client profile
  - [ ] User type


# Original readme
A fast, light weight and cloud native OAuth 2.0 Server based on microservices architecture 
built on top of light-4j and light-rest-4j frameworks. 

[Stack Overflow](https://stackoverflow.com/questions/tagged/light-4j) |
[Google Group](https://groups.google.com/forum/#!forum/light-4j) |
[Gitter Chat](https://gitter.im/networknt/light-oauth2) |
[Subreddit](https://www.reddit.com/r/lightapi/) |
[Youtube Channel](https://www.youtube.com/channel/UCHCRMWJVXw8iB7zKxF55Byw) |
[Documentation](https://doc.networknt.com/service/oauth/) |
[Contribution Guide](https://doc.networknt.com/contribute/) |

[![Build Status](https://travis-ci.org/networknt/light-oauth2.svg?branch=master)](https://travis-ci.org/networknt/light-oauth2)

Light platform follows security first design and we have provided an OAuth 2.0 provider
light-oauth2 which is based on light-4j and light-rest-4j frameworks with 7 microservices.
Some of the services implement the OAuth 2.0 specifications and others implement some
extensions to make OAuth more suitable to protect service to service communication, other 
styles of services like GraphQL, RPC and Event Driven, Key management and distribution,
service registration, token scope calculation and token exchange.    

## Why this OAuth 2.0 Authorization Server

### Fast and small memory footprint to lower production cost.

It can support 60000 user login and get authorization code redirect and can generate 
700 access tokens per second on my laptop. 

It has 7 microservices connected with in-memory data grid and each service can be
scaled individually.


### More secure than other implementations

OAuth 2.0 is just a specification and a lot of details are in the individual
implementation. Our implementation has a lot of extensions and enhancements 
for additional security and prevent users making mistakes. For example, we
have added an additional client type called "trusted" and only this type of
client can issue resource owner password credentials grant type. 

### More deployment options

You can deploy all services or just deploy the services for your use cases. You can
deploy token and code service to DMZ and all others internal for maximum security.
You can have several token services or deploy token service as sidecar pattern in
each node. You can start more instance of key service on the day that your public
key certificate for signature verification is changed and shutdown all of the but
one the next day. You can take the full advantages of microservices deployment.  

### Seamlessly integration with Light-Java framework

* Built on top of light-4j and light-rest-4j
* Light-4j Client and Security modules manages most of the communications with OAuth2
* Support service on-boarding from light-portal
* Support client on-boarding from light-portal
* Support user management from light-portal
* Open sourced OpenAPI specifications for all microserivces

### Easy to integrate with your APIs or services

The OAuth2 services can be started in a docker-compose for your local development and 
can be managed by Kubernetes on official test and production environment. It exposes
RESTful APIs and can be access from all languages and applications. 

### Support multiple databases and can be extended and customized easily

Out of the box, it supports Mysql, Postgres and Oracle XE and H2 for unit tests. Other
databases can be easily added with configuration change in service.yml.


### Public key certificate distribution

With distributed security verification, JWT signature public key certificates must
but distributed to all resource servers. The traditional push approach is not
working with microservices architecture and pull approach is adopted. There is a 
key service with endpoint to retrieve public key certificate from microservices 
during runtime based on the key_id from JWT header.  

### Two tokens to support microservices architecture

Each service in a microservices application needs a subject token which identifies the
original caller (the person who logged in the original client) and an access token
which identifies the immediate caller (might be another microservices). Both tokens
will be verified with scopes to the API endpoint level. Additional claims in these
tokens will be used for fine-grained authorization which happens within the business
context. 

### Token exchange for high security

Even with two tokens, we can only verify who is the original calller and which client is
the immediate caller. For some highly protected service like payment or fund transfer,
we need to ensure that the call is routed through some known services. light-oauth2
token service support token exchange and chaining so that a service can verify the
entire call tree to authorize if the call is authorized or not. 

### Service registration for scope calculation

light-oauth2 has a service registration to allow all service to be registered with service
id and all endpoints as well as scopes for the endpoint. During client registration, you
can link a client to services/endpoints and the scope of the client can be calculated
and updated in client table. This avoids developers to pass in scopes when getting
access token as there might be hundreds of them for a client that accesses dozens of
microservices. 

### All activities are audited 

A database audit handler has been wired into all light-oauth2 services to log each
activity across services with sensitive info masked. In the future we will put these
logs into AI stream processing to identify abnormal behaviors just like normal service
log processing.  

### OAuth2 server, portal and light-4j to form ecosystem

[light-java](https://github.com/networknt/light-java) to build API

[light-oauth2](https://github.com/networknt/light-oauth2) to control API access

[light-portal](https://github.com/networknt/light-portal) to manage clients and APIs

## Introduction

This [introduction](https://doc.networknt.com/service/oauth/introduction/) document contains all the basic concept of OAuth 2.0 specification and how it work in general. 

## Getting started

The easiest way to start using light-oauth2 in your development environment is through
docker-compose in light-docker repository. Please refer to [getting started](https://doc.networknt.com/getting-started/light-oauth2/) for more information. 

## Architecture

There are some key decision points that are documented in [architecture](https://doc.networknt.com/service/oauth/architecture/) section.

## Documentation

The detailed [service document](https://doc.networknt.com/service/oauth/service/) help users to understand how each individual service
works and the specification for each services. It also contains information on which scenarios will trigger what kind of errors. 

## Tutorial

There are [tutorials](https://doc.networknt.com/tutorial/oauth/) for each service that shows how to use the most common use cases with examples. 

## Reference

There are vast amount of information about OAuth 2.0 specifications and implementations. 
Here are some important [references](https://doc.networknt.com/service/oauth/reference/) that can help you to understand OAuth 2.0 Authorization.

