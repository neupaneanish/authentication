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
