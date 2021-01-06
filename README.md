# sql-proxy

The SQL Proxy allows a user with the appropriate permissions to connect to a
PlanetScale database without having to deal with IP whitelisting or SSL
certificates manually. It works by opening unix/tcp sockets on the local
machine and proxying connections to the associated Database instances when the
sockets are used.

