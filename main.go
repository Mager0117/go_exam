package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// User struct represents the customer table
type User struct {
	ID          int    `json:"id"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	Address     string `json:"address"`
}

// LoginRequest struct to handle incoming login JSON
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

var db *sql.DB

func main() {
	var err error
	dsn := "cp_65011212083:65011212083@csmsu@tcp(202.28.34.197:3306)/cp_65011212083?collation=utf8mb4_unicode_ci&parseTime=true"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Database connection failed: ", err)
	}
	defer db.Close()

	r := gin.Default()
	r.POST("/auth/login", loginHandler)

	r.Run(":8080") // Start the server
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var storedHashedPassword string
	var user User

	query := "SELECT customer_id, first_name, last_name, email, phone_number, address, password FROM customer WHERE email = ?"
	err := db.QueryRow(query, req.Email).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.PhoneNumber, &user.Address, &storedHashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Compare hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Return user data without password
	c.JSON(http.StatusOK, user)
}
