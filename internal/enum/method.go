package enum

type Method string

const (
	MethodLogin          = "login"
	MethodForgetPassword = "forgetPassword"
	MethodRegister       = "register"
)

func (m Method) Valid() bool {
	switch m {
	case MethodLogin, MethodForgetPassword, MethodRegister:
		return true
	default:
		return false
	}
}
