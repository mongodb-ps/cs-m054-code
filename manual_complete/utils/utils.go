package utils

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestEncrypted(field interface{}) bool {
	binaryField, ok := field.(primitive.Binary)
	if !ok || (ok && binaryField.Subtype != 6) {
		return false
	}
	return true
}
