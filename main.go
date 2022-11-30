package main

import (
	"encoding/json"
	"net/http"
	"log"
)

type person struct {
	First string
}

func main() {
	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)
	http.ListenAndServe(":8080", nil)
}

func encode(w http.ResponseWriter, r *http.Request) {
	person1 := person {
		First: "Jenny",
	};

	err := json.NewEncoder(w).Encode(person1)
	if err != nil {
		log.Println("Got bad data!")
	}
}

func decode(w http.ResponseWriter, r *http.Request) {
	var person1 person
	
	err := json.NewDecoder(r.Body).Decode(&person1)
	if err != nil {
		log.Println("Decode bad data", err)
	}

	log.Println("Person:", person1)
}

