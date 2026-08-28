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
	SecurityMethodChangePassword   SecurityMethod = "changePassword"
	SecurityMethodEnableTwoFactor  SecurityMethod = "enableTwoFactor"
	SecurityMethodDisableTwoFactor SecurityMethod = "disableTwoFactor"
)

func (m SecurityMethod) Valid() bool {
	switch m {
	case SecurityMethodChangePassword, SecurityMethodEnableTwoFactor, SecurityMethodDisableTwoFactor:
		return true
	default:
		return false
	}
}

type VerificationMethod string

const (
	VerificationMethodAccount   = "account"
	VerificationMethodEmail     = "email"
	VerificationMethodTwoFactor = "twoFactor"
	VerificationMethodReset     = "reset"
)

func (m VerificationMethod) Valid() bool {
	switch m {
	case VerificationMethodAccount, VerificationMethodEmail, VerificationMethodTwoFactor, VerificationMethodReset:
		return true
	default:
		return false
	}
}
