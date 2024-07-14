package utils

import (
	"os"
	"path/filepath"
)

func CreateDir(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// Directory does not exist, so create it
		err := os.Mkdir(dirPath, 0755) // 0755 is the Unix permission mode
		if err != nil {
			return err
		}
	}

	return nil
}

func WriteFile(filePath string, data []byte) error {
	dirPath := filepath.Dir(filePath)
	if err := CreateDir(dirPath); err != nil {
		return err
	}

	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return err
	}

	return nil
}
