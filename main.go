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

// ChangePasswordRequest struct to handle password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"` // Min 6 characters
}

var db *sql.DB

func main() {
	var err error
	// Use DSN format for MySQL connection
	dsn := "cp_65011212083:65011212083@csmsu@tcp(202.28.34.197:3306)/cp_65011212083?collation=utf8mb4_unicode_ci&parseTime=true"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Database connection failed: ", err)
	}
	defer db.Close()

	r := gin.Default()
	r.POST("/auth/login", loginHandler)
	r.POST("/auth/change-password", changePasswordHandler) // New endpoint for password change

	r.Run(":8080") // Start the server
}

// loginHandler handles user login
func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var storedHashedPassword string
	var user User

	// Query to fetch the user from the database
	query := "SELECT customer_id, first_name, last_name, email, phone_number, address, password FROM customer WHERE email = ?"
	err := db.QueryRow(query, req.Email).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.PhoneNumber, &user.Address, &storedHashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No user found with this email"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying database: " + err.Error()})
		return
	}

	// Log the stored password and input password for debugging
	log.Printf("Stored hashed password: %s", storedHashedPassword)
	log.Printf("Input password: %s", req.Password)

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(req.Password))
	if err != nil {
		log.Printf("Password comparison failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		return
	}

	// Return user data without password
	c.JSON(http.StatusOK, user)
}

// changePasswordHandler handles password change
func changePasswordHandler(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Assume we get the logged-in user's email (In a real application, use authentication to get the current user's info)
	userEmail := "user@example.com" // Placeholder - replace with real user email from session or token

	var storedHashedPassword string
	// Fetch user details from the database
	query := "SELECT password FROM customer WHERE email = ?"
	err := db.QueryRow(query, userEmail).Scan(&storedHashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No user found with this email"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying database: " + err.Error()})
		return
	}

	// Check if the old password is correct
	if err := bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(req.OldPassword)); err != nil {
		log.Printf("Old password comparison failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect old password"})
		return
	}

	// Hash the new password
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing new password"})
		return
	}

	// Update the password in the database
	updateQuery := "UPDATE customer SET password = ? WHERE email = ?"
	_, err = db.Exec(updateQuery, newHashedPassword, userEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating password"})
		return
	}

	// Return success message
	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}
