package apdu_test

import (
	"github.com/nvx/go-apdu"
	"reflect"
	"testing"
)

func TestParseCapdu(t *testing.T) {
	t.Parallel()

	type args struct {
		c []byte
	}

	tests := []struct {
		name    string
		args    args
		want    apdu.Capdu
		wantErr bool
	}{
		{
			name:    "error: invalid length",
			args:    args{c: []byte{0x00, 0xA4, 0x04}},
			wantErr: true,
		},
		{
			name:    "error: standard length LC too big",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			wantErr: true,
		},
		{
			name:    "error: extended length LC too big",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}},
			wantErr: true,
		},
		{
			name:    "error: extended length LC too small",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			wantErr: true,
		},
		{
			name:    "Case 1",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Ne: 0},
			wantErr: false,
		},
		{
			name:    "Case 2 standard length LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x00}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Ne: 256},
			wantErr: false,
		},
		{
			name:    "Case 2 standard length LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Ne: 5},
			wantErr: false,
		},
		{
			name:    "Case 2 extended length LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x00}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Ne: 65536},
			wantErr: false,
		},
		{
			name:    "Case 2 extended length LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x01, 0x01}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Ne: 257},
			wantErr: false,
		},
		{
			name:    "Case 3 standard length",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 0},
			wantErr: false,
		},
		{
			name:    "extended length CASE 3",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 0},
			wantErr: false,
		},
		{
			name:    "Case 4 standard length  LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 256},
			wantErr: false,
		},
		{
			name:    "Case 4 standard length  LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x20}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 32},
			wantErr: false,
		},
		{
			name:    "extended length CASE 4 LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 65536},
			wantErr: false,
		},
		{
			name:    "extended length CASE 4 LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x01, 0x01}},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 257},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := apdu.ParseCapdu(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCapdu() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCapdu() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCapduHexString(t *testing.T) {
	t.Parallel()

	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    apdu.Capdu
		wantErr bool
	}{
		{
			name:    "error: uneven number bytes",
			args:    args{s: "000102030"},
			wantErr: true,
		},
		{
			name:    "error: invalid length",
			args:    args{s: "000102"},
			wantErr: true,
		},
		{
			name:    "error: invalid characters",
			args:    args{"s:00010203GG"},
			wantErr: true,
		},
		{
			name:    "standard length CASE 1",
			args:    args{s: "00A40401"},
			want:    apdu.Capdu{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := apdu.ParseCapduHexString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCapduHexString() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCapduHexString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapdu_Bytes(t *testing.T) {
	t.Parallel()

	extendedData := make([]byte, 65535)
	for i := range extendedData {
		extendedData[i] = 0xFF
	}

	tooExtendedData := make([]byte, 65536)

	type fields struct {
		CLA  byte
		INS  byte
		P1   byte
		P2   byte
		Data []byte
		Ne   int
	}

	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name:    "standard length CASE 1",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 0},
			want:    []byte{0x00, 0xA4, 0x04, 0x01},
			wantErr: false,
		},
		{
			name:    "standard length CASE 2 LE unequal zero",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 255},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0xFF},
			wantErr: false,
		},
		{
			name:    "standard length CASE 2 LE equal zero",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 256},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x00},
			wantErr: false,
		},
		{
			name:    "standard length CASE 3",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x3}, Ne: 0},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x03, 0x01, 0x02, 0x03},
			wantErr: false,
		},
		{
			name:    "standard length CASE 4",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 3},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x02, 0x01, 0x02, 0x03},
			wantErr: false,
		},
		{
			name:    "extended length CASE 2 LE unequal zero",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 65535},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF},
			wantErr: false,
		},
		{
			name:    "extended length CASE 2 LE equal zero",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 65536},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "error: ne invalid CASE 2",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 65537},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "extended length CASE 3",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 0},
			want:    append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...),
			wantErr: false,
		},
		{
			name:    "error: invalid length CASE 3",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 0},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "extended length CASE 4 LE unequal zero",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 65535},
			want:    append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0xFF, 0xFF}...),
			wantErr: false,
		},
		{
			name:    "extended length CASE 4 LE equal zero",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 65536},
			want:    append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0x00, 0x00}...),
			wantErr: false,
		},
		{
			name:    "error: data extended length CASE 4",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 255},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: ne invalid length CASE 4",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 65537},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := apdu.Capdu{
				CLA:  tt.fields.CLA,
				INS:  tt.fields.INS,
				P1:   tt.fields.P1,
				P2:   tt.fields.P2,
				Data: tt.fields.Data,
				Ne:   tt.fields.Ne,
			}
			got, err := c.Bytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("Bytes() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Bytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapdu_IsExtendedLength(t *testing.T) {
	t.Parallel()

	extendedData := make([]byte, 256)
	for i := range extendedData {
		extendedData[i] = 0xFF
	}

	standardData := make([]byte, 255)
	for i := range standardData {
		standardData[i] = 0xFF
	}

	type fields struct {
		CLA  byte
		INS  byte
		P1   byte
		P2   byte
		Data []byte
		Ne   int
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "extended length ne",
			fields: fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Ne: 257},
			want:   true,
		},
		{
			name:   "extended length data",
			fields: fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 256},
			want:   true,
		},
		{
			name:   "standard length",
			fields: fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: standardData, Ne: 256},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := apdu.Capdu{
				CLA:  tt.fields.CLA,
				INS:  tt.fields.INS,
				P1:   tt.fields.P1,
				P2:   tt.fields.P2,
				Data: tt.fields.Data,
				Ne:   tt.fields.Ne,
			}
			if got := c.IsExtendedLength(); got != tt.want {
				t.Errorf("IsExtendedLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapdu_String(t *testing.T) {
	t.Parallel()

	type fields struct {
		CLA  byte
		INS  byte
		P1   byte
		P2   byte
		Data []byte
		Ne   int
	}

	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name:    "to string",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 3},
			want:    "00A4040102010203",
			wantErr: false,
		},
		{
			name:    "error: invalid ne",
			fields:  fields{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 65537},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := apdu.Capdu{
				CLA:  tt.fields.CLA,
				INS:  tt.fields.INS,
				P1:   tt.fields.P1,
				P2:   tt.fields.P2,
				Data: tt.fields.Data,
				Ne:   tt.fields.Ne,
			}
			got, err := c.String()
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("String() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func benchmarkParseCapdu(b *testing.B, by []byte) {
	b.Helper()

	b.ReportAllocs()

	for b.Loop() {
		_, _ = apdu.ParseCapdu(by)
	}
}

func BenchmarkParseCapduCase1(b *testing.B) {
	benchmarkParseCapdu(b, []byte{0x00, 0xAA, 0xBB, 0xCC})
}

func BenchmarkParseCapduCase2Std(b *testing.B) {
	benchmarkParseCapdu(b, []byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD})
}

func BenchmarkParseCapduCase3Std(b *testing.B) {
	benchmarkParseCapdu(b, []byte{0x00, 0xAA, 0xBB, 0xCC, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05})
}

func BenchmarkParseCapduCase4Std(b *testing.B) {
	benchmarkParseCapdu(b, []byte{0x00, 0xAA, 0xBB, 0xCC, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF})
}

func BenchmarkParseCapduCase2Ext(b *testing.B) {
	benchmarkParseCapdu(b, []byte{0x00, 0xAA, 0xBB, 0xCC, 0x00, 0xDD, 0xEE})
}

func BenchmarkParseCapduCase3Ext(b *testing.B) {
	benchmarkParseCapdu(b, []byte{0x00, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05})
}

func BenchmarkParseCapduCase4Ext(b *testing.B) {
	benchmarkParseCapdu(b, []byte{0x00, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0xFF})
}

func benchmarkParseCapduHexString(b *testing.B, s string) {
	b.Helper()

	b.ReportAllocs()

	for b.Loop() {
		_, _ = apdu.ParseCapduHexString(s)
	}
}

func BenchmarkParseCapduHexStringCase1(b *testing.B) {
	benchmarkParseCapduHexString(b, "00AABBCC")
}

func BenchmarkParseCapduHexStringCase2Std(b *testing.B) {
	benchmarkParseCapduHexString(b, "00AABBCCDD")
}

func BenchmarkParseCapduHexStringCase3Std(b *testing.B) {
	benchmarkParseCapduHexString(b, "00AABBCC050102030405")
}

func BenchmarkParseCapduHexStringCase4Std(b *testing.B) {
	benchmarkParseCapduHexString(b, "00AABBCC050102030405FF")
}

func BenchmarkParseCapduHexStringCase2Ext(b *testing.B) {
	benchmarkParseCapduHexString(b, "00AABBCC00DDEE")
}

func BenchmarkParseCapduHexStringCase3Ext(b *testing.B) {
	benchmarkParseCapduHexString(b, "00AABBCC0000050102030405")
}

func BenchmarkParseCapduHexStringCase4Ext(b *testing.B) {
	benchmarkParseCapduHexString(b, "00AABBCC000005010203040500FF")
}

func benchmarkCapduBytes(b *testing.B, c apdu.Capdu) {
	b.Helper()

	b.ReportAllocs()

	for b.Loop() {
		_, _ = c.Bytes()
	}
}

func BenchmarkCapdu_BytesCase1(b *testing.B) {
	benchmarkCapduBytes(b, apdu.Capdu{CLA: 0x00, INS: 0xAA, P1: 0xBB, P2: 0xCC})
}

func BenchmarkCapdu_BytesCase2Std(b *testing.B) {
	benchmarkCapduBytes(b, apdu.Capdu{CLA: 0x00, INS: 0xAA, P1: 0xBB, P2: 0xCC, Ne: 0xDD})
}

func BenchmarkCapdu_BytesCase3Std(b *testing.B) {
	benchmarkCapduBytes(b, apdu.Capdu{CLA: 0x00, INS: 0xAA, P1: 0xBB, P2: 0xCC, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}})
}

func BenchmarkCapdu_BytesCase4Std(b *testing.B) {
	benchmarkCapduBytes(b, apdu.Capdu{CLA: 0x00, INS: 0xAA, P1: 0xBB, P2: 0xCC, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 255})
}

func BenchmarkCapdu_BytesCase2Ext(b *testing.B) {
	benchmarkCapduBytes(b, apdu.Capdu{CLA: 0x00, INS: 0xAA, P1: 0xBB, P2: 0xCC, Ne: 65535})
}

func BenchmarkCapdu_BytesCase3Ext(b *testing.B) {
	benchmarkCapduBytes(b, apdu.Capdu{CLA: 0x00, INS: 0xAA, P1: 0xBB, P2: 0xCC, Data: make([]byte, 256)})
}

func BenchmarkCapdu_BytesCase4Ext(b *testing.B) {
	benchmarkCapduBytes(b, apdu.Capdu{CLA: 0x00, INS: 0xAA, P1: 0xBB, P2: 0xCC, Data: make([]byte, 256), Ne: 65536})
}
