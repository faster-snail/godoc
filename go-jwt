package auth

import (
	"time"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

const (
	//SECREATKETY 加密密钥
	SECREATKETY = "opsbible"
)


//GenerateTocken 生成一个tocken  添加入用户名，以便于解析获取用户
func GenerateTocken(user string) (string,error){
	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Second * 300).Unix()
	claims["iat"] = time.Now().Unix()
	claims["aud"] = user
	token.Claims = claims

	str,e := token.SignedString([]byte(SECREATKETY))
	if e != nil {
		return "",e
	}
	return str,nil
}

//ParseTocken 解析密钥为原始payload 返回用户名
func ParseTocken(tockenStr string) (string,bool) {
	token, err := jwt.Parse(tockenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(SECREATKETY), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		
		s := fmt.Sprintf("%v",claims["aud"])
		return s, true
	}
	return err.Error(), false
}
