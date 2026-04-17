package parser

import (
	"encoding"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// Public API

// Parser reads and writes HCL config files.
type Parser struct {
	path string
}

func NewParser(path string) *Parser {
	return &Parser{path: path}
}

// Unmarshal decodes the HCL file at p.path into output.
func (p *Parser) Unmarshal(output any) error {
	if p.path == "" {
		return def.ErrEmptyConfigPath
	}
	abs, err := filepath.Abs(p.path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	return newDecoder().decodeHCL(data, filepath.Base(abs), output)
}

// MarshalFile encodes input as HCL and writes it atomically to p.path.
func (p *Parser) MarshalFile(input any) error {
	return MarshalFile(p.path, input)
}

// MarshalBytes encodes input as HCL and returns the raw bytes.
func MarshalBytes(input any) ([]byte, error) {
	return newEncoder().encode(input)
}

// Marshal encodes input as HCL and writes it to writer.
func Marshal(writer io.Writer, input any) error {
	data, err := newEncoder().encode(input)
	if err != nil {
		return fmt.Errorf("encode HCL: %w", err)
	}
	_, err = writer.Write(data)
	return err
}

// MarshalFile encodes input as HCL and writes it atomically to path.
func MarshalFile(path string, input any) error {
	if path == "" {
		return def.ErrEmptyConfigPath
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	data, err := newEncoder().encode(input)
	if err != nil {
		return fmt.Errorf("encode HCL: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), expect.DirPerm); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, data, expect.FilePerm); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp config: %w", err)
	}
	return nil
}

// LoadGlobal parses a global config file and validates its version.
func LoadGlobal(path string) (*alaye.Global, error) {
	if path == "" {
		return nil, fmt.Errorf("config path cannot be empty")
	}
	var global alaye.Global
	if err := NewParser(path).Unmarshal(&global); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
	}
	if global.Version != def.ConfigFormatVersion {
		if global.Version < def.ConfigFormatVersion {
			return nil, fmt.Errorf(
				"config version mismatch: file v%d, expected v%d. "+
					"Please update %s to version = %d and restructure 'rate_limits'",
				global.Version, def.ConfigFormatVersion,
				filepath.Base(path), def.ConfigFormatVersion,
			)
		}
		return nil, fmt.Errorf(
			"config version mismatch: file v%d, binary expects v%d. "+
				"Please update your configuration",
			global.Version, def.ConfigFormatVersion,
		)
	}
	return &global, nil
}

// ParseHostConfig parses a host config file.
func ParseHostConfig(path string) (*alaye.Host, error) {
	var host alaye.Host
	if err := NewParser(path).Unmarshal(&host); err != nil {
		return nil, err
	}
	return &host, nil
}

// ValidateHCL reports whether data is syntactically valid HCL.
func ValidateHCL(data []byte) error {
	_, diags := hclsyntax.ParseConfig(data, "<input>", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("HCL syntax error: %s", formatDiagnostics(diags))
	}
	return nil
}

// Decoder

type decoder struct {
	ctx *hcl.EvalContext
}

func newDecoder() *decoder {
	return &decoder{ctx: buildEvalContext()}
}

func (d *decoder) decodeHCL(data []byte, filename string, output any) error {
	file, diags := hclsyntax.ParseConfig(data, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("%s: %s", filename, formatDiagnostics(diags))
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return fmt.Errorf("%s: unexpected body type", filename)
	}
	return d.decodeBody(body, reflect.ValueOf(output))
}

func (d *decoder) decodeBody(body *hclsyntax.Body, v reflect.Value) error {
	v = deref(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	for i := range t.NumField() {
		field := v.Field(i)
		if !field.CanSet() {
			continue
		}
		ft := t.Field(i)
		name, kind := parseTag(ft.Tag.Get("hcl"))
		if name == "" || name == "-" {
			continue
		}
		switch kind {
		case "attr", "optional":
			if err := d.decodeAttr(body, name, field); err != nil {
				return fmt.Errorf("attribute %q: %w", name, err)
			}
		case "block":
			if err := d.decodeBlock(body, name, field); err != nil {
				return fmt.Errorf("block %q: %w", name, err)
			}
		case "label":
			// labels are applied by decodeBlock, not here
		}
	}
	return nil
}

func (d *decoder) decodeAttr(body *hclsyntax.Body, name string, field reflect.Value) error {
	attr, exists := body.Attributes[name]
	if !exists {
		return nil
	}
	val, diags := attr.Expr.Value(d.ctx)
	if diags.HasErrors() {
		if isUnknownAttrDiag(diags) {
			return nil
		}
		return fmt.Errorf("%s", formatDiagnostics(diags))
	}
	return d.setField(field, val)
}

func (d *decoder) decodeBlock(body *hclsyntax.Body, blockType string, field reflect.Value) error {
	elemType := field.Type()

	// Slice of blocks
	if elemType.Kind() == reflect.Slice {
		return d.decodeBlockSlice(body, blockType, field, elemType)
	}

	// Single block — find the first match
	var matched *hclsyntax.Block
	for _, b := range body.Blocks {
		if b.Type == blockType {
			matched = b
			break
		}
	}
	if matched == nil {
		return nil
	}

	// Pointer to struct
	if elemType.Kind() == reflect.Ptr {
		ptr := reflect.New(elemType.Elem())
		if err := d.applyLabels(matched.Labels, ptr.Elem()); err != nil {
			return err
		}
		if err := d.decodeBody(matched.Body, ptr.Elem()); err != nil {
			return err
		}
		field.Set(ptr)
		return nil
	}

	// Value struct
	if err := d.applyLabels(matched.Labels, field); err != nil {
		return err
	}
	return d.decodeBody(matched.Body, field)
}

func (d *decoder) decodeBlockSlice(body *hclsyntax.Body, blockType string, field reflect.Value, sliceType reflect.Type) error {
	elemType := sliceType.Elem()
	isPtr := elemType.Kind() == reflect.Ptr
	baseType := elemType
	if isPtr {
		baseType = elemType.Elem()
	}
	for _, b := range body.Blocks {
		if b.Type != blockType {
			continue
		}
		elem := reflect.New(baseType).Elem()
		if err := d.applyLabels(b.Labels, elem); err != nil {
			return err
		}
		if err := d.decodeBody(b.Body, elem); err != nil {
			return err
		}
		if isPtr {
			ptr := reflect.New(baseType)
			ptr.Elem().Set(elem)
			field.Set(reflect.Append(field, ptr))
		} else {
			field.Set(reflect.Append(field, elem))
		}
	}
	return nil
}

func (d *decoder) applyLabels(labels []string, v reflect.Value) error {
	v = deref(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	li := 0
	for i := range t.NumField() {
		_, kind := parseTag(t.Field(i).Tag.Get("hcl"))
		if kind != "label" {
			continue
		}
		if li >= len(labels) {
			break
		}
		if f := v.Field(i); f.CanSet() && f.Kind() == reflect.String {
			f.SetString(labels[li])
		}
		li++
	}
	return nil
}

func (d *decoder) setField(field reflect.Value, val cty.Value) error {
	if !val.IsKnown() || val.IsNull() {
		return nil
	}
	// TextUnmarshaler covers Toggle, Duration, Value, Folder, WebRoot, etc.
	if tu, ok := textUnmarshaler(field); ok {
		text, err := ctyToString(val)
		if err != nil {
			return err
		}
		return tu.UnmarshalText([]byte(text))
	}
	// bare time.Duration (not alaye.Duration)
	if field.Type() == reflect.TypeOf(time.Duration(0)) {
		s, err := ctyToString(val)
		if err != nil {
			return err
		}
		dur, err := parseDuration(s)
		if err != nil {
			return err
		}
		field.SetInt(int64(dur))
		return nil
	}
	switch field.Kind() {
	case reflect.String:
		s, err := ctyToString(val)
		if err != nil {
			return err
		}
		field.SetString(s)
	case reflect.Bool:
		if val.Type() == cty.Bool {
			field.SetBool(val.True())
		} else {
			s, err := ctyToString(val)
			if err != nil {
				return err
			}
			field.SetBool(s == "true" || s == "1" || s == "yes")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := ctyToInt64(val)
		if err != nil {
			return err
		}
		field.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := ctyToInt64(val)
		if err != nil {
			return err
		}
		field.SetUint(uint64(n))
	case reflect.Float32, reflect.Float64:
		f, err := ctyToFloat64(val)
		if err != nil {
			return err
		}
		field.SetFloat(f)
	case reflect.Slice:
		return d.setSlice(field, val)
	case reflect.Map:
		return d.setMap(field, val)
	default:
		return fmt.Errorf("unsupported field kind %s", field.Kind())
	}
	return nil
}

func (d *decoder) setSlice(field reflect.Value, val cty.Value) error {
	if val.Type() == cty.String {
		if field.Type().Elem().Kind() == reflect.String {
			field.Set(reflect.Append(field, reflect.ValueOf(val.AsString())))
		}
		return nil
	}
	if !val.CanIterateElements() {
		return fmt.Errorf("cannot iterate %s as slice", val.Type().FriendlyName())
	}
	elemKind := field.Type().Elem().Kind()
	it := val.ElementIterator()
	for it.Next() {
		_, v := it.Element()
		switch elemKind {
		case reflect.String:
			s, err := ctyToString(v)
			if err != nil {
				return err
			}
			field.Set(reflect.Append(field, reflect.ValueOf(s)))
		case reflect.Int:
			n, err := ctyToInt64(v)
			if err != nil {
				return err
			}
			field.Set(reflect.Append(field, reflect.ValueOf(int(n))))
		default:
			return fmt.Errorf("unsupported slice element kind %s", elemKind)
		}
	}
	return nil
}

func (d *decoder) setMap(field reflect.Value, val cty.Value) error {
	if !val.CanIterateElements() {
		return fmt.Errorf("cannot iterate %s as map", val.Type().FriendlyName())
	}
	if field.IsNil() {
		field.Set(reflect.MakeMap(field.Type()))
	}
	it := val.ElementIterator()
	for it.Next() {
		k, v := it.Element()
		ks, err := ctyToString(k)
		if err != nil {
			return err
		}
		vs, err := ctyToString(v)
		if err != nil {
			return err
		}
		field.SetMapIndex(reflect.ValueOf(ks), reflect.ValueOf(vs))
	}
	return nil
}

// Encoder

type encoder struct{}

func newEncoder() *encoder { return &encoder{} }

func (e *encoder) encode(input any) ([]byte, error) {
	f := hclwrite.NewEmptyFile()
	if err := e.writeStruct(f.Body(), reflect.ValueOf(input)); err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}

func (e *encoder) writeStruct(body *hclwrite.Body, v reflect.Value) error {
	v = deref(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	for i := range t.NumField() {
		field := v.Field(i)
		ft := t.Field(i)
		name, kind := parseTag(ft.Tag.Get("hcl"))
		if name == "" || name == "-" {
			continue
		}
		switch kind {
		case "block":
			omitempty := tagHasOption(ft.Tag.Get("hcl"), "omitempty")
			if err := e.writeBlock(body, name, field, omitempty); err != nil {
				return err
			}
		case "label":
			// labels are emitted by writeBlock, not here
		default: // attr / optional
			if tok := e.scalarTokens(field); tok != nil {
				body.SetAttributeRaw(name, tok)
			}
		}
	}
	return nil
}

func (e *encoder) writeBlock(body *hclwrite.Body, blockType string, field reflect.Value, omitempty bool) error {
	fv := deref(field)
	if !fv.IsValid() {
		return nil
	}
	// Slice of blocks — always write each element (omitempty does not apply to slices)
	if fv.Kind() == reflect.Slice {
		for j := range fv.Len() {
			elem := fv.Index(j)
			block := body.AppendNewBlock(blockType, e.blockLabels(elem))
			if err := e.writeStruct(block.Body(), elem); err != nil {
				return err
			}
		}
		return nil
	}
	// Single block: skip if omitempty and the struct would produce no output
	if omitempty && e.isEmpty(fv) {
		return nil
	}
	block := body.AppendNewBlock(blockType, e.blockLabels(fv))
	return e.writeStruct(block.Body(), fv)
}

// isEmpty reports whether a struct would produce no HCL output.
// It mirrors writeStruct's field iteration but uses isZero for attrs so that
// zero bools, zero Durations, and empty Values don't keep a block alive.
// Sub-blocks are always recursed into regardless of their own omitempty tag —
// a sub-block only counts as content if it would itself produce output.
func (e *encoder) isEmpty(v reflect.Value) bool {
	v = deref(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return true
	}
	t := v.Type()
	for i := range t.NumField() {
		field := v.Field(i)
		ft := t.Field(i)
		name, kind := parseTag(ft.Tag.Get("hcl"))
		if name == "" || name == "-" {
			continue
		}
		switch kind {
		case "label":
			continue
		case "block":
			fv := deref(field)
			if !fv.IsValid() {
				continue
			}
			if fv.Kind() == reflect.Slice {
				if fv.Len() > 0 {
					return false
				}
				continue
			}
			if !e.isEmpty(fv) {
				return false
			}
		default: // attr / optional
			if !isZero(field) {
				return false
			}
		}
	}
	return true
}

func (e *encoder) blockLabels(v reflect.Value) []string {
	v = deref(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	var labels []string
	t := v.Type()
	for i := range t.NumField() {
		_, kind := parseTag(t.Field(i).Tag.Get("hcl"))
		if kind == "label" {
			labels = append(labels, fmt.Sprintf("%v", v.Field(i).Interface()))
		}
	}
	return labels
}

// scalarTokens converts a scalar field to HCL tokens for writing.
// Returns nil when the value should be omitted (zero ints, empty strings, etc.).
// Note: bool false IS written — it is a meaningful config value once set.
// Note: Duration "0s" and Value "[REDACTED]" ARE written for round-trip fidelity.
// Use isZero (not scalarTokens) to decide whether a block is empty.
func (e *encoder) scalarTokens(v reflect.Value) hclwrite.Tokens {
	v = deref(v)
	if !v.IsValid() {
		return nil
	}
	// TextMarshaler covers Toggle, Duration, Value, Folder, WebRoot, TlsMode, etc.
	if tm, ok := v.Interface().(interface{ MarshalText() ([]byte, error) }); ok {
		text, err := tm.MarshalText()
		if err != nil || len(text) == 0 || string(text) == "unknown" {
			return nil
		}
		return hclwrite.TokensForValue(cty.StringVal(string(text)))
	}
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if s == "" {
			return nil
		}
		return hclwrite.TokensForValue(cty.StringVal(s))
	case reflect.Bool:
		return hclwrite.TokensForValue(cty.BoolVal(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if n == 0 {
			return nil
		}
		return hclwrite.TokensForValue(cty.NumberIntVal(n))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := v.Uint()
		if n == 0 {
			return nil
		}
		return hclwrite.TokensForValue(cty.NumberUIntVal(n))
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if f == 0 {
			return nil
		}
		return hclwrite.TokensForValue(cty.NumberFloatVal(f))
	case reflect.Slice:
		if v.Len() == 0 {
			return nil
		}
		vals := make([]cty.Value, v.Len())
		for i := range v.Len() {
			vals[i] = cty.StringVal(fmt.Sprintf("%v", v.Index(i).Interface()))
		}
		return hclwrite.TokensForValue(cty.ListVal(vals))
	}
	return nil
}

// Shared helpers

// isZero reports whether v is the zero value for its kind.
// Stricter than scalarTokens: bool false, Duration 0, and empty string all
// return true. Used only by isEmpty to decide if an omitempty block has content.
func isZero(v reflect.Value) bool {
	v = deref(v)
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return v.IsNil()
	}
	return false
}

// deref follows pointer indirection, returning the zero Value for nil pointers.
func deref(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

// parseTag splits an hcl struct tag into its name and kind.
// e.g. `hcl:"web,block,omitempty"` → ("web", "block")
func parseTag(tag string) (name, kind string) {
	if tag == "" {
		return "", ""
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if len(parts) > 1 {
		kind = parts[1]
	}
	return name, kind
}

// tagHasOption reports whether an hcl tag contains the given option.
// e.g. tagHasOption(`hcl:"tls,block,omitempty"`, "omitempty") → true
func tagHasOption(tag, option string) bool {
	parts := strings.Split(tag, ",")
	for _, p := range parts[1:] {
		if p == option {
			return true
		}
	}
	return false
}

// textUnmarshaler returns the encoding.TextUnmarshaler for field, if any.
func textUnmarshaler(field reflect.Value) (encoding.TextUnmarshaler, bool) {
	if field.CanAddr() {
		if tu, ok := field.Addr().Interface().(encoding.TextUnmarshaler); ok {
			return tu, true
		}
	}
	if tu, ok := field.Interface().(encoding.TextUnmarshaler); ok {
		return tu, true
	}
	return nil, false
}

// buildEvalContext constructs the HCL evaluation context with env vars and
// standard string functions available inside config files.
func buildEvalContext() *hcl.EvalContext {
	envMap := make(map[string]cty.Value)
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = cty.StringVal(v)
		}
	}
	var envVal cty.Value
	if len(envMap) == 0 {
		envVal = cty.EmptyObjectVal
	} else {
		envVal = cty.MapVal(envMap)
	}
	return &hcl.EvalContext{
		Variables: map[string]cty.Value{"env": envVal},
		Functions: map[string]function.Function{
			"lower":     stdlib.LowerFunc,
			"upper":     stdlib.UpperFunc,
			"trimspace": stdlib.TrimSpaceFunc,
			"concat":    stdlib.ConcatFunc,
			"join":      stdlib.JoinFunc,
			"format":    stdlib.FormatFunc,
		},
	}
}

// parseDuration accepts Go duration strings ("30s") and bare integers (seconds).
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid duration %q", s)
}

// isUnknownAttrDiag reports whether all diagnostics are "unknown attribute"
// errors, which we silently skip rather than fail on.
func isUnknownAttrDiag(diags hcl.Diagnostics) bool {
	for _, d := range diags {
		if d.Severity == hcl.DiagError &&
			(strings.Contains(d.Summary, "Unsupported attribute") ||
				strings.Contains(d.Summary, "Unsuitable value")) {
			continue
		}
		return false
	}
	return true
}

// formatDiagnostics formats HCL diagnostics into a single error string.
func formatDiagnostics(diags hcl.Diagnostics) string {
	var sb strings.Builder
	for _, d := range diags {
		if d.Subject != nil {
			sb.WriteString(fmt.Sprintf("%s:%d,%d: %s; %s\n",
				d.Subject.Filename,
				d.Subject.Start.Line,
				d.Subject.Start.Column,
				d.Summary,
				d.Detail,
			))
		} else {
			sb.WriteString(fmt.Sprintf("%s; %s\n", d.Summary, d.Detail))
		}
	}
	return strings.TrimSpace(sb.String())
}

// ctyToString converts a cty.Value to a Go string.
func ctyToString(val cty.Value) (string, error) {
	if !val.IsKnown() {
		return "", nil
	}
	switch val.Type() {
	case cty.String:
		return val.AsString(), nil
	case cty.Bool:
		if val.True() {
			return "true", nil
		}
		return "false", nil
	case cty.Number:
		bf := val.AsBigFloat()
		if bf.IsInt() {
			n, _ := bf.Int64()
			return fmt.Sprintf("%d", n), nil
		}
		f, _ := bf.Float64()
		return fmt.Sprintf("%g", f), nil
	default:
		return "", fmt.Errorf("cannot convert %s to string", val.Type().FriendlyName())
	}
}

// ctyToInt64 converts a cty.Value to int64.
func ctyToInt64(val cty.Value) (int64, error) {
	if val.Type() != cty.Number {
		s, err := ctyToString(val)
		if err != nil {
			return 0, err
		}
		var n int64
		if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
			return 0, fmt.Errorf("cannot convert %q to int", s)
		}
		return n, nil
	}
	n, _ := val.AsBigFloat().Int64()
	return n, nil
}

// ctyToFloat64 converts a cty.Value to float64.
func ctyToFloat64(val cty.Value) (float64, error) {
	if val.Type() != cty.Number {
		return 0, fmt.Errorf("cannot convert %s to float64", val.Type().FriendlyName())
	}
	f, _ := val.AsBigFloat().Float64()
	return f, nil
}
