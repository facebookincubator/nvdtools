package nvd

import "testing"

func TestComponentVersion_CompareTo(t *testing.T) {
	type fields struct {
		VersionParts []string
	}
	type args struct {
		v *ComponentVersion
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{
			name: "test-version-compare",
			fields: fields{
				VersionParts: ParseVersion("2.6.3").VersionParts,
			},
			args: args{
				v: ParseVersion("2.6.4"),
			},
			want: -1,
		},
		{
			name: "test-version-compare",
			fields: fields{
				VersionParts: ParseVersion("7.0.0").VersionParts,
			},
			args: args{
				v: ParseVersion("7.0.0."),
			},
			want: 0,
		},
		{
			name: "test-version-compare",
			fields: fields{
				VersionParts: ParseVersion("x.y.z").VersionParts,
			},
			args: args{
				v: ParseVersion("7.0.0"),
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cv := &ComponentVersion{
				VersionParts: tt.fields.VersionParts,
			}
			if got := cv.CompareTo(tt.args.v); got != tt.want {
				t.Errorf("ComponentVersion.CompareTo() = %v, want %v", got, tt.want)
			}
		})
	}
}
