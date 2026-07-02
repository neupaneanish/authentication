package enum

type Method string

const (
	MethodLogin          Method = "login"
	MethodForgetPassword Method = "forgetPassword"
	MethodRegister       Method = "register"
)

func (m Method) Valid() bool {
	switch m {
	case MethodLogin, MethodForgetPassword, MethodRegister:
		return true
	default:
		return false
	}
}

type SecurityMethod string

const (
	ChangePassword   SecurityMethod = "changePassword"
	TwoFactor        SecurityMethod = "twoFactor"
	DisableTwoFactor SecurityMethod = "disableTwoFactor"
)

func (m SecurityMethod) Valid() bool {
	switch m {
	case ChangePassword, TwoFactor, DisableTwoFactor:
		return true
	default:
		return false
	}
}
