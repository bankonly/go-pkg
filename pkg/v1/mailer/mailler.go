package mailer

import (
	"net/smtp"
)

var Mail smtp.Auth

/* Register email auth */
func New(mailUser, secret, smtpServer string) {
	Mail = smtp.PlainAuth(
		"",
		mailUser,
		secret,
		smtpServer,
	)
}
