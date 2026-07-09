package main

import (
	"log"
	"os"

	"github.com/apolinario0x21/small-links/internal/config"
	"github.com/apolinario0x21/small-links/internal/crypto"
	httpapi "github.com/apolinario0x21/small-links/internal/http"
	"github.com/apolinario0x21/small-links/internal/storage"
	"github.com/gin-gonic/gin"
)

func main() {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	cipher, err := crypto.New([]byte(cfg.EncryptionKey))
	if err != nil {
		log.Fatal(err)
	}

	db, err := storage.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Successfully connected to the database!")

	if err := storage.Migrate(db); err != nil {
		log.Fatal(err)
	}
	log.Println("Database migration completed.")

	server := httpapi.New(storage.NewPostgres(db), cipher)
	router := server.Router()

	log.Printf("Starting server on port %s", cfg.Port)
	router.Run(":" + cfg.Port)
}
