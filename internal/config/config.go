package config

import (
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
}

func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
