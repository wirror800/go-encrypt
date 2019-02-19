package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"
)

func main() {
	filePath := flag.String("file", "input.bin", "The file to encrypt")
	encryKey := flag.String("key", "0123456789ABCDEF", "The key of AES")
	ivKey := flag.String("iv", "", "The iv of AES")
	// encryMode := flag.String("mode", "CBC", "The encrypt mode")
	// blockSize := flag.Int("size", 32, "the block size")

	flag.Parse()

	// fmt.Println(*filePath)
	// fmt.Println(*encryKey)
	// fmt.Println(*ivKey)
	// fmt.Println(*encryMode)
	// fmt.Println(*blockSize)

	f, err := os.Open(*filePath)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	outFilename := fmt.Sprintf("%s.wencrypt", *filePath)
	randBytes := GetRandomString(512)
	aesEnc := AesEncrypt{}
	aesEnc.setKey(*encryKey, *ivKey)
	printBytes("Random", randBytes)

	arrEncrypt, err := aesEnc.Encrypt(randBytes)
	if err != nil {
		fmt.Println(arrEncrypt)
		return
	}
	WriteBytes(outFilename, arrEncrypt, true)

	ReadBlock(*filePath, 512, *encryKey, *ivKey, outFilename, processBlock)
}

func printBytes(label string, bytes []byte) {
	fmt.Printf("%s:[", label)
	for _, v := range bytes {
		fmt.Printf("%x ", v)
	}
	fmt.Println("]")
}

func processBlock(line []byte, key string, iv string, outputPath string) {
	if len(line) == 0 {
		return
	}

	aesEnc := AesEncrypt{}
	aesEnc.setKey(key, iv)
	arrEncrypt, err := aesEnc.Encrypt(line)
	if err != nil {
		fmt.Println(arrEncrypt)
		return
	}

	WriteBytes(outputPath, arrEncrypt, false) //写入文件

	// strMsg, err := aesEnc.Decrypt(arrEncrypt)
	// if err != nil {
	// 	fmt.Println(arrEncrypt)
	// 	return
	// }
	// fmt.Println(strMsg)
}

func ReadBlock(filePth string, bufSize int, key string, iv string, outputPath string, hookfn func([]byte, string, string, string)) error {
	f, err := os.Open(filePth)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, bufSize) //一次读取多少个字节
	bfRd := bufio.NewReader(f)
	for {
		n, err := bfRd.Read(buf)
		hookfn(buf[:n], key, iv, outputPath) // n 是成功读取字节数

		if err != nil { //遇到任何错误立即返回，并忽略 EOF 错误信息
			if err == io.EOF {
				return nil
			}
			return err
		}
	}

	return nil
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func WriteBytes(filename string, bytes []byte, renew bool) {
	var f *os.File
	var err error

	defer f.Close()
	// if checkFileIsExist(filename) { //如果文件存在
	// 	f, err = os.OpenFile(filename, os.O_APPEND, 0666) //打开文件
	// } else {
	// 	f, err = os.Create(filename) //创建文件
	// }
	mode := os.O_RDWR | os.O_CREATE | os.O_APPEND
	if renew {
		mode = os.O_WRONLY | os.O_TRUNC | os.O_CREATE
	}
	f, err = os.OpenFile(filename, mode, 0666)
	check(err)

	f.Write(bytes) //写入文件(字节数组)
}

func GetRandomString(length int) []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return result
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	if len(ciphertext)%blockSize == 0 {
		return ciphertext
	}
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

type AesEncrypt struct {
	key string
	iv  string
}

func (this *AesEncrypt) setKey(strKey string, strIv string) {
	this.key = strKey
	this.iv = strIv
}

func (this *AesEncrypt) getKey() []byte {
	strKey := this.key
	keyLen := len(strKey)
	if keyLen < 16 {
		panic("res key 长度不能小于16")
	}
	arrKey := []byte(strKey)
	if keyLen >= 32 {
		//取前32个字节
		return arrKey[:32]
	}
	if keyLen >= 24 {
		//取前24个字节
		return arrKey[:24]
	}
	//取前16个字节
	return arrKey[:16]
}

//加密字符串
func (this *AesEncrypt) Encrypt(origData []byte) ([]byte, error) {
	printBytes("before encode:", origData)

	//origData := []byte(strMesg)
	key := this.getKey()
	printBytes("key:", key)

	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//blockSize := aesBlockEncrypter.BlockSize()
	blockSize := aes.BlockSize

	ivStr := this.iv
	if len(this.iv) == 0 {
		ivStr = string(key)
	}
	var iv = []byte(ivStr)[:blockSize]
	printBytes("iv:", iv)

	origData = PKCS5Padding(origData, blockSize)
	printBytes("padding:", origData)
	// origData = ZeroPadding(origData, aes.BlockSize())

	aesEncrypter := cipher.NewCBCEncrypter(aesBlockEncrypter, iv)
	encrypted := make([]byte, len(origData))
	aesEncrypter.CryptBlocks(encrypted, origData)

	printBytes("after encode:", encrypted)
	return encrypted, nil
}

//解密字符串
func (this *AesEncrypt) Decrypt(src []byte) (result []byte, err error) {
	defer func() {
		//错误处理
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()

	key := this.getKey()
	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err = aes.NewCipher(key)
	if err != nil {
		return make([]byte, 0), err
	}

	//blockSize := aesBlockDecrypter.BlockSize()
	blockSize := aes.BlockSize
	ivStr := this.iv
	if len(this.iv) == 0 {
		ivStr = string(key)
	}
	var iv = []byte(ivStr)[:blockSize]

	aesDecrypter := cipher.NewCBCDecrypter(aesBlockDecrypter, iv)
	decrypted := make([]byte, len(src))
	aesDecrypter.CryptBlocks(decrypted, src)
	decrypted = PKCS5UnPadding(decrypted)
	// decrypted = ZeroUnPadding(decrypted)
	return decrypted, nil
}
