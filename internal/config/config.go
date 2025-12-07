package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	ENV                  string        `mapstructure:"ENV"`
	DBDriver             string        `mapstructure:"DB_DRIVER"`
	DBSource             string        `mapstructure:"DB_SOURCE"`
	ServerAddress        string        `mapstructure:"SERVER_ADDRESS"`
	JWTSecretKey         string        `mapstructure:"JWT_SECRET_KEY"`
	JWTHS256             bool          `mapstructure:"JWT_HS256"`
	JWTES256             bool          `mapstructure:"JWT_ES256"`
	AccessTokenDuration  time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
	RefreshTokenDuration time.Duration `mapstructure:"REFRESH_TOKEN_DURATION"`
	ECPrivateKeyPath     string        `mapstructure:"EC_PRIVATE_KEY_PATH"`
	ECPublicKeyPath      string        `mapstructure:"EC_PUBLIC_KEY_PATH"`
	GinMode              string        `mapstructure:"GIN_MODE"`
	TokenIssuer          string        `mapstructure:"TOKEN_ISSUER"`
}

func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	if err = viper.ReadInConfig(); err != nil {
		fmt.Println("No app.env file found, using environment variables only")
	}

	err = viper.Unmarshal(&config)

	if !filepath.IsAbs(config.ECPrivateKeyPath) {
		config.ECPrivateKeyPath, _ = filepath.Abs(filepath.Join(path, config.ECPrivateKeyPath))
	}
	if !filepath.IsAbs(config.ECPublicKeyPath) {
		config.ECPublicKeyPath, _ = filepath.Abs(filepath.Join(path, config.ECPublicKeyPath))
	}

	return
}

func (c Config) Validate() error {
	if c.ENV == "" {
		return errors.New("ENV is required")
	}
	if c.DBDriver == "" {
		return errors.New("DB_DRIVER is required")
	}
	if c.DBSource == "" {
		return errors.New("DB_SOURCE is required")
	}
	if c.ServerAddress == "" {
		return errors.New("SERVER_ADDRESS is required")
	}

	if !c.JWTHS256 && !c.JWTES256 {
		return errors.New("at least one of JWT_HS256 or JWT_ES256 must be true")
	}
	if c.JWTHS256 && c.JWTES256 {
		return errors.New("only one of JWT_HS256 or JWT_ES256 should be true, not both")
	}

	if c.JWTHS256 && c.JWTSecretKey == "" {
		return errors.New("JWT_SECRET_KEY is required when JWT_HS256 is true")
	}

	if c.AccessTokenDuration <= 0 {
		return fmt.Errorf("ACCESS_TOKEN_DURATION must be greater than 0, got %v", c.AccessTokenDuration)
	}
	if c.RefreshTokenDuration <= 0 {
		return fmt.Errorf("REFRESH_TOKEN_DURATION must be greater than 0, got %v", c.RefreshTokenDuration)
	}
	if c.RefreshTokenDuration <= c.AccessTokenDuration {
		return errors.New("REFRESH_TOKEN_DURATION must be longer than ACCESS_TOKEN_DURATION")
	}

	if c.ECPublicKeyPath == "" {
		return errors.New("EC_PRIVATE_KEY_PATH is required")
	}
	if c.ECPrivateKeyPath == "" {
		return errors.New("EC_PRIVATE_KEY_PATH is required")
	}

	if c.GinMode == "" {
		return errors.New("GIN_MODE is required")
	}

	switch c.ENV {
	case "development", "staging", "production":
	default:
		return fmt.Errorf("invalid ENV value '%s' (expected: development, staging, production, or test)", c.ENV)
	}

	if c.TokenIssuer == "" {
		return errors.New("TOKEN_ISSUER is required")
	}

	return nil
}
