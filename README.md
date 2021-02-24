# sql-proxy

The SQL Proxy allows a user with the appropriate permissions to connect to a
PlanetScale database without having to deal with IP whitelisting or SSL
certificates manually. It works by opening unix/tcp sockets on the local
machine and proxying connections to the associated Database instances when the
sockets are used.

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

Run the proxy by passing the `organization/database/branch` combination you want to connect:

```
sql-proxy-client --token "$(cat ~/.config/planetscale/access-token)" --instance "org/db/branch" 
```
This will run the `sql-proxy-client` on your localhost and bind to the address
`127.0.0.1:3307`. You should use this address to connect your application. As
an example, here is how you can connect with the `mysql` CLI:

```
mysql -u root -h 127.0.0.1 -P 3307
```

## Development

### Releasing a new version

To release a new version of the `sql-proxy` make sure to switch to an updated `main` branch:

```
git checkout main
git pull origin main
```

after that create a new tag and push to the repo. Make sure the version is bumped:

```
git tag -a <version> -m <comment>
git push origin <version>
```

This will trigger the CI and invoke `goreleaser`, which will then release all the appropriate packages and archives.


## Credits

The `sql-proxy` project was inspired by the [`cloud_sql_proxy`](https://github.com/GoogleCloudPlatform/cloudsql-proxy/) project. Because the proxy is meant to be used with PlanetScale Database, the following parts were rewritten from scratch:

* Authentication
* Certificate Source
* Mapping of applications to database instances

We also simplified the code base towards our own needs. 
