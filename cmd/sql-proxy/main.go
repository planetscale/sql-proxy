package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/go-sql-driver/mysql"
)

type City struct {
	ID   int
	Name string
}

func main() {
	if err := realMain(); err != nil {
		log.Fatalln(err)
	}
}

func realMain() error {
	user := flag.String("user", "root", "MySQL user")
	password := flag.String("password", "", "MySQL password")
	addr := flag.String("addr", "127.0.0.1", "MySQL network address")
	dbname := flag.String("db", "", "MySQL Database name")

	caPath := flag.String("ca", "testcerts/ca.pem", "MySQL CA Cert path")
	clientCertPath := flag.String("key", "testcerts/client-cert.pem", "MySQL Client Cert path")
	clientKeyPath := flag.String("cert", "testcerts/client-key.pem", "MySQL Client Key path")

	flag.Parse()

	rootCertPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile(*caPath)
	if err != nil {
		return err
	}

	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		log.Fatal("failed to append PEM.")
	}

	certs, err := tls.LoadX509KeyPair(*clientCertPath, *clientKeyPath)
	if err != nil {
		return err
	}

	if err := mysql.RegisterTLSConfig("custom", &tls.Config{
		RootCAs:            rootCertPool,
		Certificates:       []tls.Certificate{certs},
		InsecureSkipVerify: true, // TODO(fatih): make sure if we can disable this
		VerifyConnection: func(st tls.ConnectionState) error {
			for _, p := range st.PeerCertificates {
				fmt.Printf("p.Issuer = %+v\n", p.Issuer)
				fmt.Printf("p.Subject = %+v\n", p.Subject)
			}
			return nil
		},
	}); err != nil {
		return err
	}

	cfg := mysql.NewConfig()
	cfg.User = *user
	cfg.Passwd = *password
	cfg.Net = "tcp"
	cfg.Addr = *addr
	cfg.DBName = *dbname
	cfg.TLSConfig = "custom" // should match mysql.RegisterTLSConfig()

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return fmt.Errorf("could not open SQL: %s", err)
	}
	err = db.Ping() // check that connection is working
	if err != nil {
		return fmt.Errorf("could not ping: %s", err)
	}

	rows, err := db.Query("SELECT * FROM cities")
	defer rows.Close()
	if err != nil {
		return err
	}

	for rows.Next() {
		var city City
		err := rows.Scan(&city.ID, &city.Name)
		if err != nil {
			return err
		}

		fmt.Printf("%v\n", city)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	return nil
}
