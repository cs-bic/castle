package castle

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/cs-bic/paddle"
)

func Decrypt(data []byte, hasher func([]byte) ([]byte, error), key []byte, length int) ([]byte, error) {
	if data == nil {
		return nil, errors.New("castle.Decrypt: The data is nil")
	}
	if hasher == nil {
		return nil, errors.New("castle.Decrypt: The hasher is nil")
	}
	if key == nil {
		return nil, errors.New("castle.Decrypt: The key is nil")
	}
	if length < 0 {
		return nil, errors.New("castle.Decrypt: The length is too low")
	}

	// Strip the nonce from the data.
	nonce := data[:length]
	data = data[length:]

	// Double-XOR against the data.
	data, issue := operate(data, hasher, true, key, nonce)
	if issue != nil {
		return nil, issue
	}

	// Unpad the data.
	data, issue = paddle.Unpad(data)
	if issue != nil {
		return nil, issue
	}

	// Verify the checksum.
	checksum := []byte{}
	for {
		if len(data) == 0 {
			return nil, errors.New("castle.Decrypt: Verification of the data's checksum failed because the data was entirely consumed prior to locating the checksum's terminator")
		}
		value := data[0]
		data = data[1:]

		// Locate the checksum's terminator.
		// 46 is the decimal representation of a period in ASCII, and is used to terminate the checksum.
		if value == 46 {
			break
		}

		checksum = append(checksum, value)
	}
	checksum, issue = base64.RawURLEncoding.DecodeString(string(checksum))
	if issue != nil {
		return nil, issue
	}
	checksumOther, issue := hasher(data)
	if issue != nil {
		return nil, issue
	}
	if !bytes.Equal(checksum, checksumOther) {
		return nil, errors.New("castle.Decrypt: The checksum does not match the data")
	}

	return data, nil
}
func Encrypt(block int, data []byte, hasher func([]byte) ([]byte, error), key, nonce []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("castle.Encrypt: The data is nil")
	}
	if hasher == nil {
		return nil, errors.New("castle.Encrypt: The hasher is nil")
	}
	if key == nil {
		return nil, errors.New("castle.Encrypt: The key is nil")
	}
	if nonce == nil {
		return nil, errors.New("castle.Encrypt: The nonce is nil")
	}

	// The checksum of the data is recorded for verification during decryption.
	checksum, issue := hasher(data)
	if issue != nil {
		return nil, issue
	}
	data = append([]byte(base64.RawURLEncoding.EncodeToString(checksum)+"."), data...)

	// The data is padded to prevent attackers from accurately gauging the size of the plaintext.
	data, issue = paddle.Pad(block, data)
	if issue != nil {
		return nil, issue
	}

	// Double-XOR against the data.
	data, issue = operate(data, hasher, false, key, nonce)
	if issue != nil {
		return nil, issue
	}

	return append(nonce, data...), nil
}
func operate(data []byte, hasher func([]byte) ([]byte, error), inverted bool, key, nonce []byte) ([]byte, error) {
	digestOther, issue := hasher(append(key, nonce...))
	if issue != nil {
		return nil, issue
	}
	iterator1 := 0
	for iterator1 < len(data) {
		digest, issue := hasher(digestOther)
		if issue != nil {
			return nil, issue
		}
		digestOther, issue = hasher(digest)
		if issue != nil {
			return nil, issue
		}

		// We account for variably-sized digests.
		if len(digest) <= len(digestOther) {
			iterator2 := 0
			for iterator2 < len(digest) {
				if iterator1+iterator2 == len(data) {
					break
				}
				if inverted {
					data[iterator1+iterator2] = data[iterator1+iterator2] ^ digestOther[iterator2] ^ digest[iterator2]
				} else {
					data[iterator1+iterator2] = data[iterator1+iterator2] ^ digest[iterator2] ^ digestOther[iterator2]
				}
				iterator2++
			}
			iterator1 += iterator2
		} else {
			iterator2 := 0
			for iterator2 < len(digestOther) {
				if iterator1+iterator2 == len(data) {
					break
				}
				if inverted {
					data[iterator1+iterator2] = data[iterator1+iterator2] ^ digestOther[iterator2] ^ digest[iterator2]
				} else {
					data[iterator1+iterator2] = data[iterator1+iterator2] ^ digest[iterator2] ^ digestOther[iterator2]
				}
				iterator2++
			}
			iterator1 += iterator2
		}
	}
	return data, nil
}
