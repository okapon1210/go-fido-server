package db

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"example.com/model"
)

// db 用意するのが面倒なのでそれっぽく

var (
	credentialRecordMap  = make(map[string]model.CredentialRecord)
	userMap              = make(map[string]model.User)
	registerOptionMap    = make(map[string]model.PublicKeyCredentialCreationOptions)
	attestationOptionMap = make(map[string]model.PublicKeyCredentialRequestOptions)
)

var (
	userCredentialRecordsMap = make(map[string][]model.CredentialRecord)
	credentialUserMap        = make(map[string]model.User)
)

func SaveRegisterOption(options model.PublicKeyCredentialCreationOptions) error {
	challengeString := base64.RawURLEncoding.EncodeToString(options.Challenge)
	if _, ok := registerOptionMap[challengeString]; ok {
		return errors.New("challenge: " + challengeString + " is already exists")
	}
	registerOptionMap[challengeString] = options
	return nil
}

func GetRegisterOption(challenge string) (model.PublicKeyCredentialCreationOptions, bool) {
	option, ok := registerOptionMap[challenge]
	return option, ok
}

func DeleteRegisterOption(challenge string) {
	delete(registerOptionMap, challenge)
}

func SaveAttestationOption(options model.PublicKeyCredentialRequestOptions) error {
	challengeString := base64.RawStdEncoding.EncodeToString(options.Challenge)
	if _, ok := attestationOptionMap[challengeString]; ok {
		return errors.New("challenge: " + challengeString + " is already exists")
	}
	attestationOptionMap[challengeString] = options
	return nil
}

func GetAttestationOption(challenge string) (model.PublicKeyCredentialRequestOptions, bool) {
	option, ok := attestationOptionMap[challenge]
	return option, ok
}

func DeleteAttestationOption(challenge string) {
	delete(attestationOptionMap, challenge)
}

func SaveUser(user model.User) error {
	if _, ok := userMap[user.Name]; ok {
		return errors.New("user: " + user.Name + " is already exists")
	}
	userMap[user.Name] = user
	return nil
}

func GetUser(name string) (model.User, bool) {
	user, ok := userMap[name]
	return user, ok
}

func GetCredential(credentialId string) (model.CredentialRecord, bool) {
	cr, ok := credentialRecordMap[credentialId]
	return cr, ok
}

func SaveCredential(userName string, cr model.CredentialRecord) error {
	user, ok := GetUser(userName)
	if !ok {
		return errors.New("user: " + userName + " is not found")
	}

	idString := hex.EncodeToString(cr.Id)
	if _, ok := credentialRecordMap[idString]; ok {
		return errors.New("credentialId: " + idString + " is already exists")
	} else {
		credentialRecordMap[idString] = cr
	}

	_, ok = userCredentialRecordsMap[user.Name]
	if ok {
		userCredentialRecordsMap[userName] = append(userCredentialRecordsMap[userName], cr)
	} else {
		userCredentialRecordsMap[userName] = []model.CredentialRecord{cr}
	}

	credentialUserMap[idString] = user

	return nil
}

func UpdateCredential(cr model.CredentialRecord) error {
	user, ok := GetUserByCredentialId(hex.EncodeToString(cr.Id))
	if !ok {
		return errors.New("user is not found")
	}

	idString := hex.EncodeToString(cr.Id)
	credentialRecordMap[idString] = cr

	_, ok = userCredentialRecordsMap[user.Name]
	if ok {
		userCredentialRecordsMap[user.Name] = append(userCredentialRecordsMap[user.Name], cr)
	} else {
		userCredentialRecordsMap[user.Name] = []model.CredentialRecord{cr}
	}

	credentialUserMap[idString] = user

	return nil
}

func GetCredentialByUserName(name string) ([]model.CredentialRecord, bool) {
	crs, ok := userCredentialRecordsMap[name]
	return crs, ok
}

func GetUserByCredentialId(id string) (model.User, bool) {
	user, ok := credentialUserMap[id]
	return user, ok
}
