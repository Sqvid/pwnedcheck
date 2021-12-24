package main

import (
	"bufio"
	"crypto/sha1"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

func main() {
	gmodePtr := flag.String("g", "", "Generate a password hash file.")
	fmodePtr := flag.String("f", "", "Check a password hash file.")
	flag.Parse()

	if isFlagPassed("g") {
		if isFlagPassed("f") {
			log.Fatalln("Error: cannot specify -g and -f options together.")
		}

		buildHashFile(*gmodePtr)
		return
	} else if isFlagPassed("f") {
		checkFromFile(*fmodePtr)
		return
	}

	password := getPassword()
	passHash := fmt.Sprintf("%X", sha1.Sum(password))

	pwnStatus, pwnCount := isPwned(passHash)

	if pwnStatus {
		fmt.Printf("This password has been leaked %d times!\n", pwnCount)
		fmt.Printf("It is HIGHLY recommened that you change it immediately!\n")
	} else {
		fmt.Printf("This password was not found in any leak database.\n")
	}
}

func getPassword() []byte {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln(err)
	}

	prompt := "Password (chars won't show)>> "
	passTerm := term.NewTerminal(os.Stdin, prompt)

	password, err := passTerm.ReadPassword(prompt)
	if err != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
		if err != nil {
			log.Fatalln(err)
		}
		log.Fatalln(err)
	}

	term.Restore(int(os.Stdin.Fd()), oldState)
	if err != nil {
		log.Fatalln(err)
	}

	return []byte(password)
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func buildHashFile(hashfile string) {
	f, err := os.OpenFile(hashfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	tmpf, err := ioutil.TempFile(".", ".tmphash")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpf.Name())

	fmt.Printf("Create/Edit a hash file. No changes will be saved until a write.\n\n")
	fmt.Println("Commands:")
	fmt.Println("a - add a password to the hash file.")
	fmt.Println("w - write changes to the hash file.")
	fmt.Printf("anything else - abort all changes.\n\n")

	gcmd := "a"
	for gcmd != "w" {
		fmt.Printf(">> ")
		fmt.Scanf("%s", &gcmd)

		if gcmd == "a" {
			password := getPassword()
			fmt.Fprintf(tmpf, "%X\n", sha1.Sum(password))
			fmt.Printf("%X\n", sha1.Sum(password))
		} else if gcmd == "w" {
			_, err := tmpf.Seek(0, 0)
			if err != nil {
				log.Fatalln(err)
			}

			fileScanner := bufio.NewScanner(tmpf)
			fileScanner.Split(bufio.ScanLines)

			for fileScanner.Scan() {
				fmt.Fprintf(f, "%s\n", fileScanner.Text())
			}

			fmt.Printf("Hash file modified.\n")
		} else {
			log.Printf("No changes made. Exiting.\n")
			return
		}
	}
}

func checkFromFile(hashfile string) {
	f, err := os.Open(hashfile)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		passHash := fileScanner.Text()
		pwnStatus, pwnCount := isPwned(passHash)

		if pwnStatus {
			fmt.Printf("%s has been leaked %d times!\n", passHash[:5], pwnCount)
		}
	}
}

func isPwned(passHash string) (bool, int) {
	// API expects first five characters of the hash.
	reqUrl := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", passHash[:5])
	resp, err := http.Get(reqUrl)
	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Convert the body to a carriage return delimited string.
	pwnList := strings.Split(string(body), "\r\n")
	var pwnStatus bool
	var pwnCount int

	for _, pwned := range pwnList {
		splitPwned := strings.Split(pwned, ":")
		hashEnd := splitPwned[0]

		if hashEnd == passHash[5:] {
			pwnStatus = true
			pwnCount, err = strconv.Atoi(splitPwned[1])
			if err != nil {
				log.Println(err)
			}
		}
	}

	return pwnStatus, pwnCount
}
