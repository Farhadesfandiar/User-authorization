package commands

import (
	"src/app/mongo"

	"github.com/confetti-framework/contract/inter"
	"github.com/kamva/mgm/v3"
)

// ExampleCommand to give you an example of what a command might look like.
// type ExampleCommand struct {
// 	FirstFlag string `short:"f" flag:"first" description:"Configure your first flag." required:"true"`
// }
type PostReq struct {
	Email    string `flag:"email"`
	Password string `flag:"pass"`
}

// Name of the command
// func (t ExampleCommand) Name() string {
// 	return "example:commandqqq"
// }
func (t PostReq) Name() string {
	return "req:post"
}

// Description of the command
// func (t ExampleCommand) Description() string {
// 	return "heeeyYou can adjust this command to your wishes."
// }
func (t PostReq) Description() string {
	return "Generate a post request to the app"
}

// Handle contains the logic of the command
// func (t ExampleCommand) Handle(c inter.Cli) inter.ExitCode {
// 	c.Info("Value in fist flag: %s", t.FirstFlag)
// 	return inter.Success
// }
func (t PostReq) Handle(c inter.Cli) inter.ExitCode {
	// generate a new request
	// cevab:= inter.Request.Make()
	// req, err := http.NewRequest()
	b := mongo.Init()

	if b {
		user := NewUser("ali@gmail.com", "P@ssw0rd")
		// Make sure to pass the model by reference.
		err := mgm.Coll(user).Create(user)
		if err != nil {
			c.Info("Data is NOT inserted: %s", err)
		} else {
			c.Info("Data IS inserted: %s", err)
		}
	}
	c.Info("the email is: %s", t.Email)
	return inter.Success
}

type User struct {
	mgm.DefaultModel `bson:",inline"`
	Contact          string `json:"contact" bson:"contact"`
	Password         string `json:"password" bson:"password"`
	// Phone            string `json:"phone" bson:"phone"`
}

func NewUser(email string, pass string) *User {
	return &User{
		Contact:  email,
		Password: pass,
	}
}
