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
	// OffsetCLA defines the offset to the CLA byte of a cAPDU.
	OffsetCLA = 0
	// OffsetINS defines the offset to the INS byte of a cAPDU.
	OffsetINS = 1
	// OffsetP1 defines the offset to the P1 byte of a cAPDU.
	OffsetP1 = 2
	// OffsetP2 defines the offset to the P2 byte of a cAPDU.
	OffsetP2 = 3
	// OffsetLcStandard defines the offset to the LC byte of a standard cAPDU.
	OffsetLcStandard = 4
	// OffsetLcExtended defines the offset to the LC byte of an extended cAPDU.
	OffsetLcExtended = 5
	// OffsetCdataStandard defines the offset to the beginning of the data field of a standard cAPDU.
	OffsetCdataStandard = 5
	// OffsetCdataExtended defines the offset to the beginning of the data field of an extended cAPDU.
	OffsetCdataExtended = 7
	// MaxLenCommandDataStandard defines the maximum command data length of a standard cAPDU.
	MaxLenCommandDataStandard = 255
	// MaxLenCommandDataExtended defines the maximum command data length of an extended cAPDU.
	MaxLenCommandDataExtended = 65535
	// LenHeader defines the length of the header of an APDU.
	LenHeader = 4
	// LenLcStandard defines the length of the Lc of a standard APDU.
	LenLcStandard = 1
	// LenLeStandard defines the length of the Le of a standard APDU.
	LenLeStandard = 1
	// LenLcExtended defines the length of the Lc of an extended APDU.
	LenLcExtended = 3
	// LenLeExtended defines the length of the Le of an extended APDU.
	LenLeExtended = 2
	packageTag    = "apdu"
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

	// STANDARD CASE 2 command: HEADER | Le
	if len(c) == LenHeader+LenLeStandard {
		// in this case, no Lc is present
		ne := int(c[OffsetLcStandard])
		if ne == 0 {
			return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: MaxLenResponseDataStandard}, nil
		}

		return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: ne}, nil
	}

	// Handle extended APDUs indicated by 00 byte after header and not standard case 2
	if c[OffsetLcStandard] == 0x00 {
		// EXTENDED CASE 2 command: HEADER | Le
		// in this case no Lc is present, but the two byte Le with leading zero byte
		if len(c) == LenHeader+1+LenLeExtended {
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
		// Normally this should have the leading 00 byte before Le when Lc is absent if this is really extended, or
		// if standard the Lc byte should have been omitted when there is no command.
		// The sanest interpretation is this should have been a standard case 2 but the Lc byte was accidentally included
		// For safety only handle the case of Ne == 256 as this is the only case seen in the wild.
		if len(c) == LenHeader+2 {
			le := c[5]
			if le != 0 {
				return Capdu{}, fmt.Errorf("%s: invalid Le value %d in HID hack handler", packageTag, le)
			}
			return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Ne: 256}, nil
		}

		bodyLen := len(c) - LenHeader

		lc := int(binary.BigEndian.Uint16(c[OffsetLcExtended:]))
		if lc != bodyLen-LenLcExtended && lc != bodyLen-LenLcExtended-LenLeExtended {
			return Capdu{}, fmt.Errorf("%s: invalid Lc value - Lc indicates data length %d", packageTag, lc)
		}

		data := c[OffsetCdataExtended : OffsetCdataExtended+lc]

		// EXTENDED CASE 3 command: HEADER | Lc | DATA
		if len(c) == LenHeader+LenLcExtended+len(data) {
			return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: 0}, nil
		}

		// EXTENDED CASE 4 command: HEADER | Lc | DATA | Le
		ne := 0
		le := int(binary.BigEndian.Uint16(c[len(c)-2:]))
		if le == 0x00 {
			ne = MaxLenResponseDataExtended
		} else {
			ne = le
		}

		return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: ne}, nil
	}

	bodyLen := len(c) - LenHeader

	// check if Lc indicates valid length
	lc := int(c[OffsetLcStandard])
	if lc != bodyLen-LenLcStandard && lc != bodyLen-LenLcStandard-1 {
		return Capdu{}, fmt.Errorf("%s: invalid Lc value - Lc indicates length %d", packageTag, lc)
	}

	data := c[OffsetCdataStandard : OffsetCdataStandard+lc]

	// STANDARD CASE 3 command: HEADER | Lc | DATA
	if len(c) == LenHeader+LenLcStandard+len(data) {
		return Capdu{CLA: c[OffsetCLA], INS: c[OffsetINS], P1: c[OffsetP1], P2: c[OffsetP2], Data: data}, nil
	}

	var ne int
	// STANDARD CASE 4 command: HEADER | Lc | DATA | Le
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

	if dataLen > MaxLenCommandDataStandard || c.Ne > MaxLenResponseDataStandard {
		return c.BytesExtended()
	}

	switch {
	case len(c.Data) == 0 && c.Ne == 0:
		// CASE 1: HEADER
		return []byte{c.CLA, c.INS, c.P1, c.P2}, nil
	case len(c.Data) == 0 && c.Ne > 0:
		// CASE 2: HEADER | Le
		return []byte{c.CLA, c.INS, c.P1, c.P2, (byte)((c.Ne) & 0xFF)}, nil
	case len(c.Data) != 0 && c.Ne == 0:
		// CASE 3: HEADER | Lc | DATA
		result := make([]byte, 0, LenHeader+LenLcStandard+dataLen)
		result = append(result, c.CLA, c.INS, c.P1, c.P2, byte(dataLen))
		result = append(result, c.Data...)

		return result, nil
	}

	// CASE 4: HEADER | Lc | DATA | Le
	result := make([]byte, 0, LenHeader+LenLcStandard+dataLen+LenLeStandard)
	result = append(result, c.CLA, c.INS, c.P1, c.P2, byte(dataLen))
	result = append(result, c.Data...)
	result = append(result, byte(c.Ne))

	return result, nil
}

// BytesExtended returns the byte representation of the Capdu forcing extended form.
// If both Nc and Ne are 0 then Ne will be treated as MaxLenResponseDataExtended to force extended APDU form
func (c Capdu) BytesExtended() ([]byte, error) {
	dataLen := len(c.Data)

	if dataLen > MaxLenCommandDataExtended {
		return nil, fmt.Errorf("%s: len of Capdu.Data %d exceeds maximum allowed length of %d", packageTag, len(c.Data), MaxLenCommandDataExtended)
	}

	if c.Ne > MaxLenResponseDataExtended {
		return nil, fmt.Errorf("%s: ne %d exceeds maximum allowed length of %d", packageTag, len(c.Data), MaxLenResponseDataExtended)
	}

	var leLen int
	if c.Ne > 0 {
		// if there is no Nc nor Ne then the Le bytes are covered by the Lc bytes in the buffer
		leLen = LenLeExtended
	}

	result := make([]byte, 0, LenHeader+LenLcExtended+dataLen+leLen)
	result = append(result, c.CLA, c.INS, c.P1, c.P2, 0x00)
	if dataLen > 0 {
		result = append(result, (byte)((dataLen>>8)&0xFF), (byte)(dataLen&0xFF))
		result = append(result, c.Data...)
	}
	if c.Ne > 0 || dataLen == 0 {
		// technically can't have an extended payload with both Nc == 0 and Ne == 0, so force adding a max length Ne
		result = append(result, (byte)((c.Ne>>8)&0xFF), (byte)(c.Ne&0xFF))
	}

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
