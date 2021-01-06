package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
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
	addr := flag.String("addr", "", "MySQL network address")
	dbname := flag.String("db", "", "MySQL Database name")

	flag.Parse()

	fmt.Printf("*addr = %+v\n", *addr)

	cfg := &mysql.Config{
		User:                 *user,
		Passwd:               *password,
		Net:                  "tcp",
		Addr:                 *addr,
		DBName:               *dbname,
		AllowNativePasswords: true,
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}

	// check that connection is working
	err = db.Ping()
	if err != nil {
		return err
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
