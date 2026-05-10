package session

type User struct {
	UserID      string
	EmployeeID  string
	DisplayName string
	Roles       []string
	Groups      []string
}

type ValidationResult struct {
	User User
}
