package apdu

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
)

const (
	// MaxLenResponseDataStandard defines the maximum response data length of a standard length R-APDU.
	MaxLenResponseDataStandard int = 256
	// MaxLenResponseDataExtended defines the maximum response data length of an extended length R-APDU.
	MaxLenResponseDataExtended int = 65536
	// LenResponseTrailer defines the length of the trailer of a Response APDU.
	LenResponseTrailer int = 2
)

// Rapdu is a Response APDU.
type Rapdu struct {
	Data []byte // Data is the data field.
	SW1  byte   // SW1 is the first byte of a status word.
	SW2  byte   // SW2 is the second byte of a status word.
}

func (r Rapdu) SW() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

func (r Rapdu) LogValue() slog.Value {
	return slog.GroupValue(slog.String("status", fmt.Sprintf("%04X", r.SW())), slog.String("data", fmt.Sprintf("%X", r.Data)))
}

// ParseRapdu parses a Response APDU and returns a Rapdu.
func ParseRapdu(b []byte) (_ Rapdu, err error) {
	if len(b) < LenResponseTrailer || len(b) > 65538 {
		return Rapdu{}, fmt.Errorf("%s: invalid length - a RAPDU must consist of at least 2 byte and maximum of 65538 byte, got %d", packageTag, len(b))
	}

	if len(b) == LenResponseTrailer {
		return Rapdu{SW1: b[0], SW2: b[1]}, nil
	}

	return Rapdu{Data: b[:len(b)-LenResponseTrailer], SW1: b[len(b)-2], SW2: b[len(b)-1]}, nil
}

// ParseRapduHexString decodes the hex-string representation of a Response APDU, calls ParseRapdu and returns a Rapdu.
func ParseRapduHexString(s string) (Rapdu, error) {
	if len(s)%2 != 0 {
		return Rapdu{}, fmt.Errorf("%s: uneven number of hex characters", packageTag)
	}

	if len(s) < 4 || len(s) > 131076 {
		return Rapdu{}, fmt.Errorf("%s: invalid length of hex string - a RAPDU must consist of at least 2 byte and maximum of 65538 byte, got %d", packageTag, len(s)/2)
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Rapdu{}, fmt.Errorf("%w: %s: hex conversion error", err, packageTag)
	}

	return ParseRapdu(b)
}

// Bytes returns the byte representation of the RAPDU.
func (r Rapdu) Bytes() ([]byte, error) {
	if len(r.Data) > MaxLenResponseDataExtended {
		return nil, fmt.Errorf("%s: len of Rapdu.Data %d exceeds maximum allowed length of %d", packageTag, len(r.Data), MaxLenResponseDataExtended)
	}

	b := make([]byte, 0, len(r.Data)+2)
	b = append(b, r.Data...)
	b = append(b, r.SW1, r.SW2)

	return b, nil
}

// String calls Bytes and returns the hex encoded string representation of the RAPDU.
func (r Rapdu) String() (string, error) {
	b, err := r.Bytes()
	if err != nil {
		return "", err
	}

	return strings.ToUpper(hex.EncodeToString(b)), nil
}

// IsSuccess returns true if the RAPDU indicates the successful execution of a command ('0x61xx' or '0x9000'), otherwise false.
func (r Rapdu) IsSuccess() bool {
	return r.SW1 == 0x61 || (r.SW() == 0x9000)
}

// IsWarning returns true if the RAPDU indicates the execution of a command with a warning ('0x62xx' or '0x63xx'), otherwise false.
func (r Rapdu) IsWarning() bool {
	return r.SW1 == 0x62 || r.SW1 == 0x63
}

// IsError returns true if the RAPDU indicates an error during the execution of a command ('0x64xx', '0x65xx' or from '0x67xx' to 0x6Fxx'), otherwise false.
func (r Rapdu) IsError() bool {
	return (r.SW1 == 0x64 || r.SW1 == 0x65) || (r.SW1 >= 0x67 && r.SW1 <= 0x6F)
}
