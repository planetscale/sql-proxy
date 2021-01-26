# sql-proxy

The SQL Proxy allows a user with the appropriate permissions to connect to a
PlanetScale database without having to deal with IP whitelisting or SSL
certificates manually. It works by opening unix/tcp sockets on the local
machine and proxying connections to the associated Database instances when the
sockets are used.

## Usage

Install the proxy

```go
go get github.com/planetscale/sql-proxy/cmd/sql-proxy-client
```

Authenticate with [`pscale`](https://github.com/planetscale/cli):

```
pscale auth login
```

Run the proxy by passing the `organization/database/branch` combination you want to connect:

```
sql-proxy-client --token "$(cat ~/.config/planetscale/access-token)" --instance "org/db/branch" 
```
This will run the `sql-proxy-client` on your localhost and bind to
`127.0.0.1:3307`. You should use this address to connect your application. As
an example, here is how you can connect with the `mysql` CLI:

```
mysql -u root -h 127.0.0.1 -P 3307
```

## Credits

The `sql-proxy` project was inspired by the [`cloud_sql_proxy`](https://github.com/GoogleCloudPlatform/cloudsql-proxy/) project. Because the proxy is meant to be used with PlanetScale Database, the following parts were rewritten from scratch:

* Authentication
* Certificate Source
* Mapping of applications to database instances

We also simplified the code base towards our own needs. 
