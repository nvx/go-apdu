// Package apdu implements parsing and conversion of Application Protocol Data Units (APDU) which is the communication format between a card and off-card applications. The format of the APDU is defined in ISO specification 7816-4.
// The package has support for extended length APDUs as well.
package apdu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
)

const (
	// OffsetCLA defines the offset to the CLA byte of a C-APDU.
	OffsetCLA int = 0
	// OffsetINS defines the offset to the INS byte of a C-APDU.
	OffsetINS int = 1
	// OffsetP1 defines the offset to the P1 byte of a C-APDU.
	OffsetP1 int = 2
	// OffsetP2 defines the offset to the P2 byte of a C-APDU.
	OffsetP2 int = 3
	// OffsetLcStandard defines the offset to the LC byte of a standard length C-APDU.
	OffsetLcStandard int = 4
	// OffsetLcExtended defines the offset to the LC byte of an extended length C-APDU.
	OffsetLcExtended int = 5
	// OffsetCdataStandard defines the offset to the beginning of the data field of a standard length C-APDU.
	OffsetCdataStandard int = 5
	// OffsetCdataExtended defines the offset to the beginning of the data field of an extended length C-APDU.
	OffsetCdataExtended int = 7
	// MaxLenCommandDataStandard defines the maximum command data length of a standard length C-APDU.
	MaxLenCommandDataStandard int = 255
	// MaxLenCommandDataExtended defines the maximum command data length of an extended length C-APDU.
	MaxLenCommandDataExtended int = 65535
	// LenHeader defines the length of the header of an APDU.
	LenHeader int = 4
	// LenLCStandard defines the length of the LC of a standard length APDU.
	LenLCStandard int = 1
	// LenLCExtended defines the length of the LC of an extended length APDU.
	LenLCExtended int    = 3
	packageTag    string = "apdu"
)

// Capdu is a Command APDU.
type Capdu struct {
	CLA  byte   // CLA is the class byte.
	INS  byte   // INS is the instruction byte.
	P1   byte   // P1 is the p1 byte.
	P2   byte   // P2 is the p2 byte.
	Data []byte // Data is the data field.
	Ne   int    // Ne is the total number of expected response data byte (not LE encoded).
}

// ParseCapdu parses a Command APDU and returns a Capdu.
func ParseCapdu(c []byte) (Capdu, error) {
	if len(c) < LenHeader || len(c) > 65544 {
		return Capdu{}, fmt.Errorf("%s: invalid length - Capdu must consist of at least 4 byte and maximum of 65544 byte, got %d", packageTag, len(c))
	}

	// CASE 1 command: only HEADER
	if len(c) == LenHeader {
		return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2]}, nil
	}

	// check for zero byte
	if c[OffsetLcStandard] == 0x00 {
		// check for extended length Capdu
		if len(c[OffsetLcExtended:]) > 0 {
			// EXTENDED CASE 2 command: HEADER | LE
			// in this case no LC is present, but the two byte LE with leading zero byte
			if len(c) == LenHeader+LenLCExtended {
				ne := 0
				le := int(binary.BigEndian.Uint16(c[OffsetLcExtended:]))

				if le == 0x00 {
					ne = MaxLenResponseDataExtended
				} else {
					ne = le
				}

				return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Ne: ne}, nil
			}

			// Dodgy broken HID reader request
			if len(c) == LenHeader+2 {
				le := binary.BigEndian.Uint16(c[OffsetLcStandard:])
				if le != 0 {
					return Capdu{}, fmt.Errorf("%s: invalid Le value %d in HID hack handler", packageTag, le)
				}
				return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Ne: 256}, nil
			}

			bodyLen := len(c) - LenHeader

			lc := int(binary.BigEndian.Uint16(c[OffsetLcExtended : OffsetLcExtended+2]))
			if lc != bodyLen-LenLCExtended && lc != bodyLen-LenLCExtended-2 {
				return Capdu{}, fmt.Errorf("%s: invalid LC value - LC indicates data length %d", packageTag, lc)
			}

			data := c[OffsetCdataExtended : OffsetCdataExtended+lc]

			// EXTENDED CASE 3 command: HEADER | LC | DATA
			if len(c) == LenHeader+LenLCExtended+len(data) {
				return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: 0}, nil
			}

			// EXTENDED CASE 4 command: HEADER | LC | DATA | LE
			ne := 0

			le := int(binary.BigEndian.Uint16(c[len(c)-2:]))

			if le == 0x00 {
				ne = MaxLenResponseDataExtended
			} else {
				ne = le
			}

			return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: ne}, nil
		}
	}

	ne := 0
	// STANDARD CASE 2 command: HEADER | LE
	if len(c) == LenHeader+LenLCStandard {
		// in this case, no LC is present
		ne = int(c[OffsetLcStandard])
		if ne == 0 {
			return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: MaxLenResponseDataStandard}, nil
		}

		return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: ne}, nil
	}

	bodyLen := len(c) - LenHeader

	// check if lc indicates valid length
	lc := int(c[OffsetLcStandard])
	if lc != bodyLen-LenLCStandard && lc != bodyLen-LenLCStandard-1 {
		return Capdu{}, fmt.Errorf("%s: invalid Lc value - Lc indicates length %d", packageTag, lc)
	}

	data := c[OffsetCdataStandard : OffsetCdataStandard+lc]

	// STANDARD CASE 3 command: HEADER | LC | DATA
	if len(c) == LenHeader+LenLCStandard+len(data) {
		return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: data}, nil
	}

	// STANDARD CASE 4 command: HEADER | LC | DATA | LE
	if le := int(c[len(c)-1]); le == 0 {
		ne = MaxLenResponseDataStandard
	} else {
		ne = le
	}

	return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: ne}, nil
}

// ParseCapduHexString decodes the hex-string representation of a Command APDU, calls ParseCapdu and returns a Capdu.
func ParseCapduHexString(s string) (Capdu, error) {
	if len(s)%2 != 0 {
		return Capdu{}, fmt.Errorf("%s: uneven number of hex characters", packageTag)
	}

	if len(s) < 8 || len(s) > 65544*2 {
		return Capdu{}, fmt.Errorf("%s: invalid length of hex string - a Capdu must consist of at least 4 byte and maximum of 65544 byte, got %d", packageTag, len(s)/2)
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Capdu{}, fmt.Errorf("%w: %s: hex conversion error", err, packageTag)
	}

	return ParseCapdu(b)
}

// Bytes returns the byte representation of the Capdu.
func (c Capdu) Bytes() ([]byte, error) {
	dataLen := len(c.Data)

	if dataLen > MaxLenCommandDataExtended {
		return nil, fmt.Errorf("%s: len of Capdu.Data %d exceeds maximum allowed length of %d", packageTag, len(c.Data), MaxLenCommandDataExtended)
	}

	if c.Ne > MaxLenResponseDataExtended {
		return nil, fmt.Errorf("%s: ne %d exceeds maximum allowed length of %d", packageTag, len(c.Data), MaxLenResponseDataExtended)
	}

	switch {
	case len(c.Data) == 0 && c.Ne == 0:
		// CASE 1: HEADER
		return []byte{c.CLA, c.INS, c.P1, c.P2}, nil
	case len(c.Data) == 0 && c.Ne > 0:
		// CASE 2: HEADER | LE
		if c.Ne > MaxLenResponseDataStandard {
			le := make([]byte, LenLCExtended) // first byte is zero byte, so LE length is equal to LC length

			if c.Ne == MaxLenResponseDataExtended {
				le[1] = 0x00
				le[2] = 0x00
			} else {
				le[1] = (byte)((c.Ne >> 8) & 0xFF)
				le[2] = (byte)(c.Ne & 0xFF)
			}

			result := make([]byte, 0, LenHeader+LenLCExtended)
			result = append(result, c.CLA, c.INS, c.P1, c.P2)
			result = append(result, le...)

			return result, nil
		}

		// standard format
		result := make([]byte, 0, LenHeader+LenLCStandard)
		result = append(result, c.CLA, c.INS, c.P1, c.P2)

		if c.Ne == MaxLenResponseDataStandard {
			result = append(result, 0x00)
		} else {
			result = append(result, byte(c.Ne))
		}

		return result, nil
	case len(c.Data) != 0 && c.Ne == 0:
		// CASE 3: HEADER | LC | DATA
		if len(c.Data) > MaxLenCommandDataStandard {
			// extended length format
			lc := make([]byte, LenLCExtended)
			lc[1] = (byte)((dataLen >> 8) & 0xFF)
			lc[2] = (byte)(dataLen & 0xFF)

			result := make([]byte, 0, LenHeader+LenLCExtended+dataLen)
			result = append(result, c.CLA, c.INS, c.P1, c.P2)
			result = append(result, lc...)
			result = append(result, c.Data...)

			return result, nil
		}

		// standard format
		result := make([]byte, 0, LenHeader+1+dataLen)
		result = append(result, c.CLA, c.INS, c.P1, c.P2, byte(dataLen))
		result = append(result, c.Data...)

		return result, nil
	}

	// CASE 4: HEADER | LC | DATA | LE
	if c.Ne > MaxLenResponseDataStandard || len(c.Data) > MaxLenCommandDataStandard {
		return c.BytesExtended()
	}

	// standard format
	result := make([]byte, 0, LenHeader+LenLCStandard+dataLen+1)
	result = append(result, c.CLA, c.INS, c.P1, c.P2, byte(dataLen))
	result = append(result, c.Data...)
	result = append(result, byte(c.Ne))

	return result, nil
}

// BytesExtended returns the byte representation of the Capdu forcing extended form.
func (c Capdu) BytesExtended() ([]byte, error) {
	dataLen := len(c.Data)

	if dataLen > MaxLenCommandDataExtended {
		return nil, fmt.Errorf("%s: len of Capdu.Data %d exceeds maximum allowed length of %d", packageTag, len(c.Data), MaxLenCommandDataExtended)
	}

	if c.Ne > MaxLenResponseDataExtended {
		return nil, fmt.Errorf("%s: ne %d exceeds maximum allowed length of %d", packageTag, len(c.Data), MaxLenResponseDataExtended)
	}

	// extended length format
	lc := make([]byte, LenLCExtended) // first byte is zero byte
	lc[1] = (byte)((dataLen >> 8) & 0xFF)
	lc[2] = (byte)(dataLen & 0xFF)

	le := make([]byte, 2)

	if c.Ne == MaxLenResponseDataExtended {
		le[0] = 0x00
		le[1] = 0x00
	} else {
		le[0] = (byte)((c.Ne >> 8) & 0xFF)
		le[1] = (byte)(c.Ne & 0xFF)
	}

	result := make([]byte, 0, LenHeader+LenLCExtended+dataLen+len(le))
	result = append(result, c.CLA, c.INS, c.P1, c.P2)
	result = append(result, lc...)
	result = append(result, c.Data...)
	result = append(result, le...)

	return result, nil
}

// String calls Bytes and returns the hex encoded string representation of the Capdu.
func (c Capdu) String() (string, error) {
	b, err := c.Bytes()
	if err != nil {
		return "", err
	}

	return strings.ToUpper(hex.EncodeToString(b)), nil
}

func (c Capdu) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("info", fmt.Sprintf("%02X %02X %02X %02X (%d)", c.CLA, c.INS, c.P1, c.P2, c.Ne)),
		slog.String("data", fmt.Sprintf("%X", c.Data)),
	)
}

// IsExtendedLength returns true if the Capdu has extended length (len of Data > 65535 or Ne > 65536), else false.
func (c Capdu) IsExtendedLength() bool {
	return c.Ne > MaxLenResponseDataStandard || len(c.Data) > MaxLenCommandDataStandard
}
