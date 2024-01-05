package validator

import "log"

type User struct {
	Gender string `json:"gender" validate:"enum=m-Fele"`
}

func EnumRunTest() {
	New(ValidatorConfig{})
	user := User{Gender: "m"}

	err := ValidateStruct(&user)
	log.Println(err)
}
