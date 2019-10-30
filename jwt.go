package goJWT

package utils

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// TokenUtility is the datastructure that holds application name and sign key for the application JWTs
type TokenUtility struct {
	ID, App, Audience, SignKey string
	Expiry                     time.Duration
}

// CustomClaims are used to customize a JWT payload
type CustomClaims struct {
	Bindle interface{} `json:"bindle"`
	jwt.StandardClaims
}

// NewTokenUtility will retirn an instance of a TokenUtility with application and signKey set
func NewTokenUtility(app, signKey string) *TokenUtility {
	return &TokenUtility{
		App:     app,
		SignKey: signKey,
		Expiry:  15,
	}
}

// GenerateToken will return a new JWT
func (tokenUtility *TokenUtility) GenerateToken(claims CustomClaims) (string, error) {
	if tokenUtility.SignKey == "" {
		log.Fatal(errors.New("There is no signKey set for this instance of TokenUtility"))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	sKey := []byte(tokenUtility.SignKey)

	return token.SignedString(sKey)
}

// GenerateClaims will return a built CustomClaims payload for use in the GenerateToken func
func (tokenUtility *TokenUtility) GenerateClaims(bindle map[string]interface{}) CustomClaims {
	claims := CustomClaims{
		bindle,
		jwt.StandardClaims{
			Id:        tokenUtility.ID,
			Audience:  tokenUtility.Audience,
			ExpiresAt: time.Now().Add(time.Minute * tokenUtility.Expiry).Unix(),
			Issuer:    tokenUtility.App,
		},
	}

	return claims
}