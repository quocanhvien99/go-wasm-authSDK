package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"syscall/js"
	"time"

	"github.com/google/uuid"
)

func main() {
	chann:=make(chan bool)
	
	js.Global().Set("authWASM", js.FuncOf(authWASM))
	<- chann

	//authenSdk("3c8ae411-60ed-4399-9342-9ad9584d5373", "a8c0ca89266db7a4d8471d8aed0b81ac")
}

func getRequestKey(requestKeyRaw string) string {
// 	pubPEM := `
// -----BEGIN PUBLIC KEY-----
// MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw9k2wbvhaH7N5GVedzqmndA7T
// 7ztd+TcbU4hWviCCXxPsqaI0FO6+n/Kmvq3/bfBS2qXJJVc8GU0x5XLSncBWmV83
// rwqRGH0KPT/PsJaptGawsUJxCq5C2fTi/YwxEMUZ/9Cd/NlsOUcxbbirfgd1KqxI
// CFXa7h3COJ9w776CjwIDAQAB
// -----END PUBLIC KEY-----`

// 	pubBlock, _ := pem.Decode([]byte(pubPEM))
// 	pubInterface, _ := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	//pubKey := pubInterface.(*rsa.PublicKey)
	
	N := new(big.Int)
	N, _ = N.SetString("124267028728638581121070787280234243051532812540007967510168589511435652130442884347795415107666368932885151439646519004848914216397604982136217735091649969247923605346596971744138557699938535359205962436207484133990056252387425951973427673411194233133650109410810406284239264280532265221886304345740418122383", 10)
	E := 65537
	pubKey := &rsa.PublicKey{N: N, E: E}

	cipherText,_ := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(requestKeyRaw))
	return base64.StdEncoding.EncodeToString(cipherText)
}
func authWASM(this js.Value, params []js.Value) interface{} {
	appId := params[0].String()
	appSecret := params[1].String()
	
	requestKeyRaw := uuid.NewString()
	requestKey := getRequestKey(requestKeyRaw)
	
	packageName := "ion-sdk-js"
	timestamp := fmt.Sprint(time.Now().UnixMilli())
	println()
	signature := appId + "|" + packageName + "|" + timestamp + "|" + appSecret

	//md5
	hashRaw := md5.Sum([]byte(signature))
	hash := hex.EncodeToString(hashRaw[:])
	
	data := fmt.Sprintf(`{ "app_id": "%s", "package_name": "%s", "hash": "%s" }`, appId, packageName, hash)

	iv := []byte(appSecret[:16])
	secretKey := requestKeyRaw[:32]

	encryptedData := AesCBCEncrypter(secretKey, iv, data)
	
	action := "/authpb.AuthService/SDKVerifyHash"
	checksum := AesCBCEncrypter("acd205251ea9a0abfccecc2bee378a63", []byte("acd205251ea9a0ab"),fmt.Sprintf("%s%s000000%s", appId, timestamp, action))
	
	reqInfo := fmt.Sprintf(`{ "appId": "%s", "checksum": "%s", "timestamp": "%s", "requestKey": "%s", "encryptedData": "%s", "secretKey": "%s", "iv": "%s" }`, appId, checksum, timestamp, requestKey, encryptedData, secretKey, iv)
	
	var resEncrypted string
	
	authApi := params[2]
	resolve := params[3]
	authApi.Invoke(reqInfo).Call("then", js.FuncOf(func(this js.Value, params []js.Value) interface{} {
		resEncrypted = params[0].String()
		//println(resEncrypted)

		res := AesCBCDecrypter(secretKey, iv, resEncrypted)

		if checkStatus(res) {
			resolve.Invoke("http://localhost:8080/public/ion-sdk.min.js")
		} else {
			resolve.Invoke(false)
		}
						
		return 0
	}))
	return 0
}

func AesCBCEncrypter(key string, iv []byte, plaintext string) string {  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}   

	origData, _ := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	// include it at the beginning of the ciphertext.  
	ciphertext := make([]byte, len(origData))  
	mode := cipher.NewCBCEncrypter(block, iv)  
	mode.CryptBlocks(ciphertext, origData)  
	return base64.StdEncoding.EncodeToString(ciphertext)
}
func AesCBCDecrypter(key string, iv []byte, ct string) string {
	ciphertext, _ := base64.StdEncoding.DecodeString(ct)  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  
	// CBC mode always works in whole blocks.  
   if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewCBCDecrypter(block, iv)  
	origData := make([]byte, len(ciphertext))

	// CryptBlocks can work in-place if the two arguments are the same.  
	mode.CryptBlocks(origData, ciphertext)  
	origData, _ = pkcs7Unpad(origData, aes.BlockSize)
	s := string(origData)  
   
	return s
}
func pkcs7Pad(ciphertext []byte, blockSize int) ([]byte, string) {
    padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...), ""
}
func pkcs7Unpad(data []byte, blocklen int) ([]byte, string) {
    if blocklen <= 0 {
        return nil, "invalid blocklen"
    }
    if len(data)%blocklen != 0 || len(data) == 0 {
        return nil, "invalid data len"
    }
    padlen := int(data[len(data)-1])
    if padlen > blocklen || padlen == 0 {
        return nil, "invalid padding"
    }
    // check padding
    pad := data[len(data)-padlen:]
    for i := 0; i < padlen; i++ {
        if pad[i] != byte(padlen) {
            return nil, "invalid padding"
        }
    }

    return data[:len(data)-padlen], ""
}

func checkStatus (res string) bool {
	if i := strings.Index(res, "message"); i > -1 {
		msg := res[i+10:i+17]
		if msg == "success" { return true }
	}
	return false
}