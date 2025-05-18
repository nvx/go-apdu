package apdu_test

import (
	"github.com/nvx/go-apdu"
	"reflect"
	"testing"
)

func TestParseRapdu(t *testing.T) {
	t.Parallel()

	type args struct {
		b []byte
	}

	tests := []struct {
		name    string
		args    args
		want    apdu.Rapdu
		wantErr bool
	}{
		{
			name:    "error: invalid length too small",
			args:    args{b: []byte{0x6A}},
			wantErr: true,
		},
		{
			name:    "error: invalid length too big",
			args:    args{b: make([]byte, 65539)},
			wantErr: true,
		},
		{
			name:    "only SW",
			args:    args{b: []byte{0x6A, 0x80}},
			want:    apdu.Rapdu{Data: nil, SW1: 0x6A, SW2: 0x80},
			wantErr: false,
		},
		{
			name:    "data and SW",
			args:    args{b: []byte{0x01, 0x02, 0x03, 0x90, 0x00}},
			want:    apdu.Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := apdu.ParseRapdu(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRapdu() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRapdu() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRapduHexString(t *testing.T) {
	t.Parallel()

	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    apdu.Rapdu
		wantErr bool
	}{
		{
			name:    "error: uneven number bytes",
			args:    args{s: "6A80A"},
			wantErr: true,
		},
		{
			name:    "error: invalid length",
			args:    args{s: "6A"},
			wantErr: true,
		},
		{
			name:    "error: invalid characters",
			args:    args{s: "FFGF6A88"},
			wantErr: true,
		},
		{
			name:    "only SW",
			args:    args{s: "6A80"},
			want:    apdu.Rapdu{Data: nil, SW1: 0x6A, SW2: 0x80},
			wantErr: false,
		},
		{
			name:    "data and SW",
			args:    args{s: "0102039000"},
			want:    apdu.Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := apdu.ParseRapduHexString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRapduHexString() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRapduHexString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_Bytes(t *testing.T) {
	t.Parallel()

	tooExtendedData := make([]byte, apdu.MaxLenResponseDataExtended+1)
	for i := range tooExtendedData {
		tooExtendedData[i] = 0xFF
	}

	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name:    "only SW",
			fields:  fields{Data: nil, SW1: 0x6A, SW2: 0x80},
			want:    []byte{0x6A, 0x80},
			wantErr: false,
		},
		{
			name:    "data and SW",
			fields:  fields{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			want:    []byte{0x01, 0x02, 0x03, 0x90, 0x00},
			wantErr: false,
		},
		{
			name:    "data and SW, truncate data",
			fields:  fields{Data: tooExtendedData, SW1: 0x90, SW2: 0x00},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := apdu.Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			got, err := r.Bytes()
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

func TestRapdu_String(t *testing.T) {
	t.Parallel()

	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name:    "trailer only",
			fields:  fields{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			want:    "0102039000",
			wantErr: false,
		},
		{
			name:    "error: invalid length",
			fields:  fields{Data: make([]byte, 65537), SW1: 0x90, SW2: 0x00},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := apdu.Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			got, err := r.String()
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

func TestRapdu_IsSuccess(t *testing.T) {
	t.Parallel()

	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "trailer only success",
			fields: fields{SW1: 0x90, SW2: 0x00},
			want:   true,
		},
		{
			name:   "trailer only success",
			fields: fields{SW1: 0x61, SW2: 0x10},
			want:   true,
		},
		{
			name:   "trailer only not success",
			fields: fields{SW1: 0x6A, SW2: 0x88},
			want:   false,
		},
		{
			name:   "trailer + data success",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			want:   true,
		},
		{
			name:   "trailer + data success",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x61, SW2: 0x03},
			want:   true,
		},
		{
			name:   "trailer + data not success",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x6A, SW2: 0x88},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := apdu.Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			if got := r.IsSuccess(); got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_IsWarning(t *testing.T) {
	t.Parallel()

	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "warning 0x62",
			fields: fields{SW1: 0x62, SW2: 0x84},
			want:   true,
		},
		{
			name:   "warning 0x63",
			fields: fields{SW1: 0x63, SW2: 0xC1},
			want:   true,
		},
		{
			name:   "success, not warning",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			want:   false,
		},
		{
			name:   "error, not warning",
			fields: fields{SW1: 0x6F, SW2: 0x00},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := apdu.Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			if got := r.IsWarning(); got != tt.want {
				t.Errorf("IsWarning() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_IsError(t *testing.T) {
	t.Parallel()

	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "error 0x64",
			fields: fields{SW1: 0x64, SW2: 0x00},
			want:   true,
		},
		{
			name:   "error 0x65",
			fields: fields{SW1: 0x65, SW2: 0x81},
			want:   true,
		},
		{
			name:   "error 0x67",
			fields: fields{SW1: 0x67, SW2: 0x00},
			want:   true,
		},
		{
			name:   "error 0x6A",
			fields: fields{SW1: 0x6A, SW2: 0x88},
			want:   true,
		},
		{
			name:   "error 0x6F",
			fields: fields{SW1: 0x6F, SW2: 0x00},
			want:   true,
		},
		{
			name:   "success, not error",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			want:   false,
		},
		{
			name:   "warning, not error",
			fields: fields{SW1: 0x63, SW2: 0x00},
			want:   false,
		},
		{
			name:   "no error, 0x66",
			fields: fields{SW1: 0x66, SW2: 0x00},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := apdu.Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			if got := r.IsError(); got != tt.want {
				t.Errorf("IsError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func benchmarkParseRapdu(b *testing.B, by []byte) {
	b.Helper()

	b.ReportAllocs()

	for b.Loop() {
		_, _ = apdu.ParseRapdu(by)
	}
}

func BenchmarkParseRapduTrailerOnly(b *testing.B) {
	benchmarkParseRapdu(b, []byte{0x90, 0x00})
}

func BenchmarkParseRapduTrailerAndData(b *testing.B) {
	benchmarkParseRapdu(b, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x90, 0x00})
}

func benchmarkParseRapduHexString(b *testing.B, s string) {
	b.Helper()

	b.ReportAllocs()

	for b.Loop() {
		_, _ = apdu.ParseRapduHexString(s)
	}
}

func BenchmarkParseRapduHexStringTrailerOnly(b *testing.B) {
	benchmarkParseRapduHexString(b, "9000")
}

func BenchmarkParseRapduHexStringTrailerAndData(b *testing.B) {
	benchmarkParseRapduHexString(b, "01020304059000")
}

func benchmarkRapduBytes(b *testing.B, c apdu.Rapdu) {
	b.Helper()

	b.ReportAllocs()

	for b.Loop() {
		_, _ = c.Bytes()
	}
}

func BenchmarkRapdu_BytesOTrailerOnly(b *testing.B) {
	benchmarkRapduBytes(b, apdu.Rapdu{SW1: 0x90, SW2: 0x00})
}

func BenchmarkRapdu_BytesTrailerAndData(b *testing.B) {
	benchmarkRapduBytes(b, apdu.Rapdu{Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, SW1: 0x90, SW2: 0x00})
}
