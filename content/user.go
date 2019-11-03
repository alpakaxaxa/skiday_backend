package content

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/bosssauce/access"
	"github.com/bosssauce/reference"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"

	"github.com/ponzu-cms/ponzu/management/editor"
	"github.com/ponzu-cms/ponzu/system/db"
	"github.com/ponzu-cms/ponzu/system/item"
)

type User struct {
	item.Item

	Partner     string `json:"partner"`
	Firstname   string `json:"firstname"`
	Lastname    string `json:"lastname"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Departure   string `json:"departure"`
	Competition string `json:"competition"`
}

type Message struct {
	Message string `json:"message"`
}

// MarshalEditor writes a buffer of html to edit a User within the CMS
// and implements editor.Editable
func (u *User) MarshalEditor() ([]byte, error) {
	view, err := editor.Form(u,
		// Take note that the first argument to these Input-like functions
		// is the string version of each User field, and must follow
		// this pattern for auto-decoding and auto-encoding reasons:
		editor.Field{
			View: editor.Checkbox("Partner", u, map[string]string{
				"label": "Partner",
			}, map[string]string{
				"true": "Yes",
			}),
		},
		editor.Field{
			View: editor.Input("Firstname", u, map[string]string{
				"label":       "Firstname",
				"type":        "text",
				"placeholder": "Enter the Firstname here",
			}),
		},
		editor.Field{
			View: editor.Input("Lastname", u, map[string]string{
				"label":       "Lastname",
				"type":        "text",
				"placeholder": "Enter the Lastname here",
			}),
		},
		editor.Field{
			View: editor.Input("Email", u, map[string]string{
				"label":       "Email",
				"type":        "text",
				"placeholder": "Enter the Email here",
			}),
		},
		editor.Field{
			View: editor.Input("Password", u, map[string]string{
				"type": "hidden",
			}),
		},
		editor.Field{
			View: reference.Select("Departure", u, map[string]string{
				"label": "Departure",
			},
				"Departure",
				`{{ .city }} {{ .time }} `,
			),
		},
		editor.Field{
			View: reference.Select("Competition", u, map[string]string{
				"label": "Competition",
			},
				"Competition",
				`{{ .title }} `,
			),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to render User editor view: %s", err.Error())
	}
	return view, nil
}

func init() {
	item.Types["User"] = func() interface{} { return new(User) }
	http.HandleFunc("/recovery-mail", recoveryMail)
	http.HandleFunc("/new-password", newPassword)
	http.HandleFunc("/login", login)
}

func (u *User) String() string {
	return fmt.Sprintf("User: %s %s", u.Firstname, u.Lastname)
}

func (u *User) Hide(res http.ResponseWriter, req *http.Request) error {
	if !access.IsOwner(req, req.Header, u.Email) {
		fmt.Fprintf(res, "You are not the owner of this content")
		return nil
	}
	return item.ErrAllowHiddenItem
}

func (u *User) Create(res http.ResponseWriter, req *http.Request) error {
	return nil
}

func (u *User) AutoApprove(res http.ResponseWriter, req *http.Request) error {
	return nil
}

func (u *User) AfterAPICreate(res http.ResponseWriter, req *http.Request) error {
	cfg := &access.Config{
		ExpireAfter:    time.Hour * 24 * 7 * 60,
		ResponseWriter: res,
		TokenStore:     req.Header,
	}
	user, err := findUserByEmail(u.Email)
	if err != nil {
		fmt.Println(err)
	}
	hashedPassword := hashUserPassword([]byte(user.Password))
	user.Password = string(hashedPassword)
	v := url.Values{}
	v.Add("password", user.Password)
	db.UpdateContent("User:"+strconv.Itoa(user.ID), v)
	grant, err := access.Grant(u.Email, user.Password, cfg)
	if err != nil {
		return err
	}
	fmt.Printf(
		"The access token for user (%s) is: %s\n",
		grant.Key, grant.Token,
	)
	db.SetRecoveryKey(user.Email)
	return nil
}

func (u *User) BeforeAPIUpdate(res http.ResponseWriter, req *http.Request) error {
	if !access.IsOwner(req, req.Header, u.Email) {
		return fmt.Errorf(
			"grant provided is not owner of PrivateEvent, from %s",
			req.RemoteAddr,
		)
	}
	return nil
}

func (u *User) Update(res http.ResponseWriter, req *http.Request) error {
	return nil
}

func (u *User) IndexContent() bool {
	return true
}

func findUserByEmail(userEmail string) (User, error) {
	var targetUser User
	rawUsers := db.ContentAll("User")
	for _, rawUser := range rawUsers {
		var user User
		err := json.Unmarshal(rawUser, &user)
		if err != nil {
			fmt.Println(err)
		}
		if user.Email == userEmail {
			targetUser = user
		}
	}
	if targetUser.ID > 0 {
		return targetUser, nil
	}
	return targetUser, fmt.Errorf("No user with mail %s", userEmail)
}

func hashUserPassword(password []byte) []byte {
	hashedPassword, err := bcrypt.GenerateFromPassword(password, 14)
	if err != nil {
		fmt.Println(err)
	}
	return hashedPassword
}

func recoveryMail(res http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		email := req.FormValue("email")

		user, err := findUserByEmail(email)
		if err != nil {
			fmt.Println(err)
		}
		if user.ID <= 0 {
			j := jsonMessage("Could not find email")
			res.Header().Set("Content-Type", "application/json")
			res.Write(j)
			return
		}
		key, err := db.RecoveryKey(email)
		if err != nil {
			fmt.Println(err)
		}
		m := gomail.NewMessage()
		m.SetHeader("From", "stephan.dint.mueller@gmail.com")
		m.SetHeader("To", email)
		m.SetHeader("Subject", "Password Recovery Bühler Skiday")
		m.SetBody("text/html", "Hey there, you tried to recover your password. Click on the following link to set your new password:<br>http://localhost:8080/new-password?email="+email+"&key="+key)

		d := gomail.NewDialer("smtp.googlemail.com", 587, "stephan.dint.mueller@gmail.com", "BdHZmWuudKgdDk1943")
		if err := d.DialAndSend(m); err != nil {
			panic(err)
		}
		j := jsonMessage("We sent an email to " + email + ". Check spam folder if you can't find the message")
		res.Header().Set("Content-Type", "application/json")
		res.Write(j)
	}
}

func newPassword(res http.ResponseWriter, req *http.Request) {
	keys := req.URL.Query()
	if len(keys) != 2 {
		j := jsonMessage("Two query parameters are needed")
		res.Header().Set("Content-Type", "application/json")
		res.Write(j)
	}
	email := keys.Get("email")
	userKey := keys.Get("key")
	if email == "" || userKey == "" {
		j := jsonMessage("Need email and corresponding password reset key")
		res.Header().Set("Content-Type", "application/json")
		res.Write(j)
	}
	key, err := db.RecoveryKey(email)
	if err != nil {
		fmt.Println(err)
	}
	if key != userKey {
		j := jsonMessage("Password reset key is wrong")
		res.Header().Set("Content-Type", "application/json")
		res.Write(j)
		return
	}
	if req.Method == "GET" {
		tmpl := `
		<!DOCTYPE html>
		<html>
		<head>
		</head>
		<style>
		{
			margin:0;
			padding:0;
			box-sizing: border-box;
		}
		
		html {
			font-size: 18px;
			font-family: 'Helvetica', 'Roboto', sans-serif;
		}
		
		body {
			overflow-x:hidden;
			overflow-y:visible;
			width:100%;
			height:auto;
			line-height:1.5;
		}
		
		.container{
			max-width: 68rem;
			width: 90%;
			margin: 0 auto;
		}
		
		section{
			margin:4vh 0 0 0;
		}
		
		.button {
			border-color: #dbdbdb;
			border-style: solid;
			border-width: 1px;
			cursor: pointer;
			justify-content: center;
			padding-bottom: calc(.5em - 1px);
			padding-left: 1em;
			padding-right: 1em;
			padding-top: calc(.5em - 1px);
			text-align: center;
			white-space: nowrap;
			color:black;
			margin: 5px 0px 5px 0px;
		}
		
		</style>
		<body>
		<section>
		<div class="container">
		<div style="display:flex;align-items:center;justify-content:center;flex-direction:column;"> 
		<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/48/Buhler_logo_RGB.svg/1920px-Buhler_logo_RGB.svg.png" width="300"> 
		<div>
		<h2>Enter your new Password here</h2>
		  <form method="POST"> 
		  <input type="password" name="password" id="password">
		  <button type="submit" class="button">Set new Password</button>
		  </form>
		<a class="tag" href="https://buhler-skiday.ch/login">Back to login page</a>
		</div>
		</div>
		<section>
		
		</body>
		</html> 
		`
		fmt.Fprintf(res, tmpl)
	}
	if req.Method == "POST" {
		req.ParseForm()
		newPassword := req.FormValue("password")
		newPasswordHashed := hashUserPassword([]byte(newPassword))
		user, err := findUserByEmail(email)
		if err != nil {
			fmt.Println(err)
		}
		user.Password = string(newPasswordHashed)
		v := url.Values{}
		v.Add("password", user.Password)
		db.UpdateContent("User:"+strconv.Itoa(user.ID), v)
		db.SetRecoveryKey(user.Email)
		return
	}
}

func login(res http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		email := req.FormValue("email")
		userPassword := req.FormValue("password")
		if email == "" || userPassword == "" {
			j := jsonMessage("Username and password needed")
			res.Header().Set("Content-Type", "application/json")
			res.Write(j)
			return
		}
		user, err := findUserByEmail(email)
		if err != nil {
			fmt.Println(err)
		}
		if user.ID <= 0 {
			j := jsonMessage("Username and password needed")
			res.Header().Set("Content-Type", "application/json")
			res.Write(j)
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userPassword))
		if err != nil {
			j := jsonMessage("Wrong email or password")
			res.Header().Set("Content-Type", "application/json")
			res.Write(j)
			return
		} else {
			cfg := &access.Config{
				ExpireAfter:    time.Hour * 24 * 7 * 60,
				ResponseWriter: res,
				TokenStore:     req.Header,
			}
			grant, err := access.Grant(email, userPassword, cfg)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Printf(
				"The access token for user (%s) is: %s\n",
				grant.Key, grant.Token,
			)
			j := jsonMessage("Successful login")
			res.Header().Set("Content-Type", "application/json")
			res.Write(j)
			return
		}
	} else {
		http.Error(res, "Only POST requests are allowed", http.StatusBadRequest)
		return
	}
}

func (u *User) FormatCSV() []string {
	// []string contains the JSON struct tags generated for your Content type
	// implementing the interface
	return []string{
		"id",
		"timestamp",
		"slug",
		"email",
		"firstname",
		"lastname",
		"departure",
		"competition",
		"partner",
	}
}

func jsonMessage(s string) []byte {
	var m Message
	m.Message = s
	rawJSON, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
	}
	return rawJSON
}
