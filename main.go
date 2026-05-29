package main

import (
	"log"
	"os"
	"time"

	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

var jwtSecret []byte

func main() {
	SetJwtSecret()
	app := fiber.New()
	app.Post("/login", Login)
	app.Post("/refresh", RefreshToken)
	app.Use(jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key: jwtSecret,
		},
	}))
	//all the routes from here are protected by jwtware
	app.Get("/user", func(c *fiber.Ctx) error {
		user := c.Locals("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		return c.JSON(fiber.Map{
			"message": "Protected route accessed",
			"userId":  claims["userid"],
		})
	})
	log.Fatal(app.Listen(":3000"))
}

func SetJwtSecret() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
	jwtSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
}

func CreateToken(userId string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"userid": userId,
		"exp":    time.Now().Add(duration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return jwtSecret, nil
	})
}

func Login(c *fiber.Ctx) error {
	var body User
	err := c.BodyParser(&body)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "invalid body",
		})
	}
	if body.Username != "sai" || body.Password != "123" {
		return c.Status(401).JSON(fiber.Map{
			"error": "invalid credentials",
		})
	}
	accessToken, err := CreateToken("1", time.Minute*15)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "cannot create access token",
		})
	}
	refreshToken, err := CreateToken("1", time.Hour*24*7)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "cannot create refresh token",
		})
	}
	return c.JSON(fiber.Map{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func RefreshToken(c *fiber.Ctx) error {
	type RefreshBody struct {
		RefreshToken string `json:"refreshToken"`
	}
	var body RefreshBody
	err := c.BodyParser(&body)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "invalid body",
		})
	}
	token, err := VerifyToken(body.RefreshToken)
	if err != nil || !token.Valid {
		return c.Status(401).JSON(fiber.Map{
			"error": "invalid refresh token",
		})
	}
	claims := token.Claims.(jwt.MapClaims)
	userId := claims["userid"].(string)
	newAccessToken, err := CreateToken(userId, time.Minute*15)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "cannot create access token",
		})
	}
	return c.JSON(fiber.Map{
		"accessToken": newAccessToken,
	})
}
