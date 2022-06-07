# sql-proxy [![Build status](https://badge.buildkite.com/ca3f602492e4918255dec82c84067f2bb2349d4a4cb85600fe.svg?branch=main)](https://buildkite.com/planetscale/sql-proxy)

The SQL Proxy allows a user with the appropriate permissions to connect to a
PlanetScale database without having to deal with IP whitelisting or SSL
certificates manually. It works by opening unix/tcp sockets on the local
machine and proxying connections to the associated Database instances when the
sockets are used.

# NOTE
This repo has been deprecated in favour of using the normal `pscale` CLI client in a container, and passing it the `connect` command with the `host` flag, which will do the same thing

## Installation

**homebrew tap** (only on macOS for now):

```
brew install planetscale/tap/pscale-proxy
```

**deb/rpm**:

Download the .deb or .rpm from the [releases](https://github.com/planetscale/sql-proxy/releases/latest) page and install with dpkg -i and rpm -i respectively.

**manually**:

Download the pre-compiled binaries from the [releases](https://github.com/planetscale/sql-proxy/releases/latest) page and copy to the desired location.

## Usage

Authenticate with [`pscale`](https://github.com/planetscale/cli):

```
pscale auth login
```

Run the proxy by passing your organization, database and the branch you want to connect:

```
sql-proxy-client --token "$(cat ~/.config/planetscale/access-token)" --org "org" --database "db" --branch "branch" 
```
This will run the `sql-proxy-client` on your localhost and bind to the address
`127.0.0.1:3307`. You should use this address to connect your application. As
an example, here is how you can connect with the `mysql` CLI:

```
mysql -u root -h 127.0.0.1 -P 3307
```

### Connecting with a Service token

To connect with a service token and service token name, use the following flags:

```
sql-proxy-client --service-token "<your_service_token>" --service-token-name "<your_service_token_name>" --org "org" --database "db" --branch "branch" 
```
## Using the Docker container

We also provide ready to use containers. To pull the latest docker image:

```
docker pull planetscale/pscale-proxy:latest
```

Here is an example to run the container and publish the proxy on host address
`127.0.0.1:3306:`

```
$ docker run -p 127.0.0.1:3306:3306 planetscale/pscale-proxy \
  --host 0.0.0.0 \
  --org "$PLANETSCALE_ORG" \
  --database "$PLANETSCALE_DATABASE" \
  --branch "$PLANETSCALE_BRANCH" \
  --service-token "$PLANETSCALE_SERVICE_TOKEN" \
  --service-token-name "$PLANETSCALE_SERVICE_TOKEN_NAME" 
```

## Credits

The `sql-proxy` project was inspired by the [`cloud_sql_proxy`](https://github.com/GoogleCloudPlatform/cloudsql-proxy/) project. Because the proxy is meant to be used with PlanetScale Database, the following parts were rewritten from scratch:

* Authentication
* Certificate Source
* Mapping of applications to database instances

We also simplified the code base towards our own needs. 
