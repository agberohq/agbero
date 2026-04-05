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
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// Parser holds the path to the configuration file being decoded.
// All decode and encode operations resolve relative to this path.
type Parser struct {
	path string
}

// NewParser constructs a Parser targeting the given file path.
// The path is resolved to absolute during Unmarshal.
func NewParser(path string) *Parser {
	return &Parser{path: path}
}

// Unmarshal reads the HCL file at the parser path and decodes it into output.
// Defaults are not applied here — callers must invoke woos.DefaultApply or woos.DefaultHost after.
func (p *Parser) Unmarshal(output any) error {
	if p.path == "" {
		return woos.ErrEmptyConfigPath
	}
	abs, err := filepath.Abs(p.path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	return decodeHCL(data, filepath.Base(abs), output)
}

// MarshalBytes encodes the value to HCL bytes using hclwrite.
// No file I/O — caller decides what to do with the bytes.
func MarshalBytes(input any) ([]byte, error) {
	return encodeHCL(input)
}

// Marshal writes encoded HCL directly to the provided writer.
// No atomic writes or temp files — pure encoding and streaming.
func Marshal(writer io.Writer, input any) error {
	data, err := encodeHCL(input)
	if err != nil {
		return fmt.Errorf("encode HCL: %w", err)
	}
	_, err = writer.Write(data)
	return err
}

// MarshalFile encodes and writes atomically to a file path using temp-and-rename.
// Use this when crash-safe persistence is required.
func MarshalFile(path string, input any) error {
	if path == "" {
		return woos.ErrEmptyConfigPath
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	data, err := encodeHCL(input)
	if err != nil {
		return fmt.Errorf("encode HCL: %w", err)
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, woos.DirPerm); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmpPath := abs + ".tmp"
	if err := os.WriteFile(tmpPath, data, woos.FilePerm); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, abs); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp config: %w", err)
	}
	return nil
}

// MarshalFile is a convenience method that uses the parser's own path.
// Encodes input and writes it atomically to the path the parser was constructed with.
func (p *Parser) MarshalFile(input any) error {
	return MarshalFile(p.path, input)
}

// LoadGlobal loads and validates the version of a global configuration file.
// Returns an error if the file is missing, malformed, or carries a mismatched version.
func LoadGlobal(path string) (*alaye.Global, error) {
	if path == "" {
		return nil, fmt.Errorf("config path cannot be empty")
	}
	var global alaye.Global
	if err := NewParser(path).Unmarshal(&global); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
	}
	if global.Version != woos.ConfigFormatVersion {
		if global.Version < woos.ConfigFormatVersion {
			return nil, fmt.Errorf(
				"config version mismatch: file v%d, expected v%d. "+
					"Please update %s to version = %d and restructure 'rate_limits'",
				global.Version, woos.ConfigFormatVersion,
				filepath.Base(path), woos.ConfigFormatVersion,
			)
		}
		return nil, fmt.Errorf(
			"config version mismatch: file v%d, binary expects v%d. "+
				"Please update your configuration",
			global.Version, woos.ConfigFormatVersion,
		)
	}
	return &global, nil
}

// ParseHostConfig loads a host configuration file from disk.
// Returns the decoded Host struct without applying defaults.
func ParseHostConfig(path string) (*alaye.Host, error) {
	var host alaye.Host
	if err := NewParser(path).Unmarshal(&host); err != nil {
		return nil, err
	}
	return &host, nil
}

// ValidateHCL performs syntax-only validation of raw HCL bytes.
// Returns nil if syntactically valid, or a diagnostic error with file position info.
func ValidateHCL(data []byte) error {
	_, diags := hclsyntax.ParseConfig(data, "<input>", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("HCL syntax error: %s", formatDiagnostics(diags))
	}
	return nil
}

// decode engine

// decodeHCL parses raw HCL bytes and maps the result into output using
// a reflection-driven walker over hclsyntax.Body. No schema is enforced —
// only attributes and blocks present in the file are decoded.
func decodeHCL(data []byte, filename string, output any) error {
	file, diags := hclsyntax.ParseConfig(data, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("%s: %s", filename, formatDiagnostics(diags))
	}
	ctx := buildEvalContext()
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return fmt.Errorf("%s: unexpected body type", filename)
	}
	return decodeBody(body, ctx, reflect.ValueOf(output))
}

// decodeBody maps an hclsyntax.Body onto a Go struct value using struct field
// hcl tags. Only fields present in the body are touched — absent fields are left
// at their Go zero values so woos defaults can fill them later.
func decodeBody(body *hclsyntax.Body, ctx *hcl.EvalContext, v reflect.Value) error {
	v = indirect(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()

	for i := range t.NumField() {
		field := v.Field(i)
		fieldType := t.Field(i)

		if !field.CanSet() {
			continue
		}

		tagName, tagKind := parseTag(fieldType.Tag.Get("hcl"))
		if tagName == "" || tagName == "-" {
			continue
		}

		switch tagKind {
		case "attr":
			attr, exists := body.Attributes[tagName]
			if !exists {
				continue
			}
			val, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() {
				if isUnknownAttrDiag(diags) {
					continue
				}
				return fmt.Errorf("attribute %q: %s", tagName, formatDiagnostics(diags))
			}
			if err := setField(field, val); err != nil {
				return fmt.Errorf("attribute %q: %w", tagName, err)
			}

		case "block":
			if err := decodeBlockField(body, ctx, tagName, field, fieldType); err != nil {
				return fmt.Errorf("block %q: %w", tagName, err)
			}

		case "label":

		default:

			attr, exists := body.Attributes[tagName]
			if !exists {
				continue
			}
			val, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() {
				if isUnknownAttrDiag(diags) {
					continue
				}
				return fmt.Errorf("attribute %q: %s", tagName, formatDiagnostics(diags))
			}
			if err := setField(field, val); err != nil {
				return fmt.Errorf("attribute %q: %w", tagName, err)
			}
		}
	}
	return nil
}

// decodeBlockField handles decoding a single block-tagged struct field.
// Supports value structs, pointer structs, and slices of structs (repeated blocks).
func decodeBlockField(
	body *hclsyntax.Body,
	ctx *hcl.EvalContext,
	blockType string,
	field reflect.Value,
	fieldType reflect.StructField,
) error {
	elemType := field.Type()
	isPtr := elemType.Kind() == reflect.Ptr
	isSlice := elemType.Kind() == reflect.Slice

	if isSlice {
		sliceElemType := elemType.Elem()
		if sliceElemType.Kind() == reflect.Ptr {
			sliceElemType = sliceElemType.Elem()
		}
		for _, block := range body.Blocks {
			if block.Type != blockType {
				continue
			}
			elem := reflect.New(sliceElemType).Elem()
			if err := applyLabels(block.Labels, elem); err != nil {
				return err
			}
			if err := decodeBody(block.Body, ctx, elem); err != nil {
				return err
			}
			if elemType.Elem().Kind() == reflect.Ptr {
				ptr := reflect.New(sliceElemType)
				ptr.Elem().Set(elem)
				field.Set(reflect.Append(field, ptr))
			} else {
				field.Set(reflect.Append(field, elem))
			}
		}
		return nil
	}

	var matchedBlock *hclsyntax.Block
	for _, block := range body.Blocks {
		if block.Type == blockType {
			matchedBlock = block
			break
		}
	}
	if matchedBlock == nil {
		return nil
	}

	if isPtr {
		ptrElemType := elemType.Elem()
		ptr := reflect.New(ptrElemType)
		if err := applyLabels(matchedBlock.Labels, ptr.Elem()); err != nil {
			return err
		}
		if err := decodeBody(matchedBlock.Body, ctx, ptr.Elem()); err != nil {
			return err
		}
		field.Set(ptr)
		return nil
	}

	if err := applyLabels(matchedBlock.Labels, field); err != nil {
		return err
	}
	return decodeBody(matchedBlock.Body, ctx, field)
}

// applyLabels sets label-tagged fields on a struct from the block's label list.
func applyLabels(labels []string, v reflect.Value) error {
	v = indirect(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()
	labelIdx := 0
	for i := range t.NumField() {
		_, kind := parseTag(t.Field(i).Tag.Get("hcl"))
		if kind != "label" {
			continue
		}
		if labelIdx >= len(labels) {
			break
		}
		f := v.Field(i)
		if f.CanSet() && f.Kind() == reflect.String {
			f.SetString(labels[labelIdx])
		}
		labelIdx++
	}
	return nil
}

// setField assigns a cty.Value to a reflect.Value using the field's Go type.
// Handles all scalar types used across the alaye structs, plus TextUnmarshaler.
func setField(field reflect.Value, val cty.Value) error {
	if !val.IsKnown() || val.IsNull() {
		return nil
	}

	if tu, ok := fieldAsTextUnmarshaler(field); ok {
		text, err := ctyToString(val)
		if err != nil {
			return err
		}
		return tu.UnmarshalText([]byte(text))
	}

	// time.Duration is int64 underneath but must be parsed from strings like "30s".
	if field.Type() == reflect.TypeOf(time.Duration(0)) {
		s, err := ctyToString(val)
		if err != nil {
			return err
		}
		d, err := parseDuration(s)
		if err != nil {
			return err
		}
		field.SetInt(int64(d))
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
		return setSliceField(field, val)

	case reflect.Map:
		return setMapField(field, val)

	default:
		return fmt.Errorf("unsupported field kind %s", field.Kind())
	}
	return nil
}

// setSliceField decodes a cty tuple or list into a []string or []int slice field.
func setSliceField(field reflect.Value, val cty.Value) error {
	if val.Type() == cty.String {
		s := val.AsString()
		if field.Type().Elem().Kind() == reflect.String {
			field.Set(reflect.Append(field, reflect.ValueOf(s)))
		}
		return nil
	}

	if !val.CanIterateElements() {
		return fmt.Errorf("cannot iterate cty value of type %s as slice", val.Type().FriendlyName())
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

// setMapField decodes a cty object into a map[string]string field.
func setMapField(field reflect.Value, val cty.Value) error {
	if !val.CanIterateElements() {
		return fmt.Errorf("cannot iterate cty value of type %s as map", val.Type().FriendlyName())
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

// fieldAsTextUnmarshaler returns the TextUnmarshaler interface if the field
// implements it, trying both pointer and value receivers.
func fieldAsTextUnmarshaler(field reflect.Value) (encoding.TextUnmarshaler, bool) {
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

// ctyToString converts any scalar cty value to its string representation.
// Used for TextUnmarshaler types and plain string fields.
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

// ctyToInt64 converts a cty number value to int64.
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
	bf := val.AsBigFloat()
	n, _ := bf.Int64()
	return n, nil
}

// ctyToFloat64 converts a cty number value to float64.
func ctyToFloat64(val cty.Value) (float64, error) {
	if val.Type() != cty.Number {
		return 0, fmt.Errorf("cannot convert %s to float64", val.Type().FriendlyName())
	}
	bf := val.AsBigFloat()
	f, _ := bf.Float64()
	return f, nil
}

// indirect unwraps pointer values until a non-pointer is reached.
func indirect(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

// parseTag splits a raw hcl struct tag into its name and kind components.
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

// eval context

// buildEvalContext constructs the HCL evaluation context used during attribute decoding.
// Environment variables are exposed under the "env" namespace as a map so that
// missing keys resolve to empty string rather than a hard decode error.
// Standard string functions are registered for use in config expressions.
func buildEvalContext() *hcl.EvalContext {
	envMap := make(map[string]cty.Value)
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = cty.StringVal(parts[1])
		}
	}

	var envVal cty.Value
	if len(envMap) == 0 {
		envVal = cty.EmptyObjectVal
	} else {
		envVal = cty.MapVal(envMap)
	}

	funcs := map[string]function.Function{
		"lower":     stdlib.LowerFunc,
		"upper":     stdlib.UpperFunc,
		"trimspace": stdlib.TrimSpaceFunc,
		"concat":    stdlib.ConcatFunc,
		"join":      stdlib.JoinFunc,
		"format":    stdlib.FormatFunc,
	}

	return &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"env": envVal,
		},
		Functions: funcs,
	}
}

// encode engine

// encodeHCL serialises a Go struct to formatted HCL bytes using hclwrite.
func encodeHCL(input any) ([]byte, error) {
	f := hclwrite.NewEmptyFile()
	if err := encodeValue(f.Body(), reflect.ValueOf(input)); err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}

// encodeValue recursively encodes a Go struct into an hclwrite.Body.
func encodeValue(body *hclwrite.Body, v reflect.Value) error {
	v = indirect(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	t := v.Type()

	for i := range t.NumField() {
		field := v.Field(i)
		fieldType := t.Field(i)

		tagName, tagKind := parseTag(fieldType.Tag.Get("hcl"))
		if tagName == "" || tagName == "-" {
			continue
		}

		switch tagKind {
		case "block":
			if err := encodeBlockField(body, tagName, field); err != nil {
				return err
			}
		case "label":

		default:
			tokens := scalarTokens(field)
			if tokens != nil {
				body.SetAttributeRaw(tagName, tokens)
			}
		}
	}
	return nil
}

// encodeBlockField writes one or more HCL blocks for a struct or slice field.
func encodeBlockField(body *hclwrite.Body, blockType string, field reflect.Value) error {
	fv := indirect(field)
	if !fv.IsValid() {
		return nil
	}

	if fv.Kind() == reflect.Slice {
		for j := range fv.Len() {
			elem := fv.Index(j)
			block := body.AppendNewBlock(blockType, blockLabels(elem))
			if err := encodeValue(block.Body(), elem); err != nil {
				return err
			}
		}
		return nil
	}

	block := body.AppendNewBlock(blockType, blockLabels(fv))
	return encodeValue(block.Body(), fv)
}

// blockLabels extracts label-tagged string field values from a struct.
func blockLabels(v reflect.Value) []string {
	v = indirect(v)
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

// scalarTokens converts a scalar Go value to hclwrite raw tokens.
// Returns nil for zero values that should be omitted from output.
func scalarTokens(v reflect.Value) hclwrite.Tokens {
	v = indirect(v)
	if !v.IsValid() {
		return nil
	}

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
			elem := v.Index(i)
			s := fmt.Sprintf("%v", elem.Interface())
			vals[i] = cty.StringVal(s)
		}
		return hclwrite.TokensForValue(cty.ListVal(vals))

	case reflect.Map:
		return nil
	}

	return nil
}

// diagnostics

// parseDuration parses a duration string ("30s", "1m") or bare integer (seconds).
// This handles time.Duration fields that cannot use TextUnmarshaler.
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

// errors, which occur when an env var key is missing from the cty map. These are
// treated as empty/zero values rather than hard errors.
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
func formatDiagnostics(diags hcl.Diagnostics) string {
	var sb strings.Builder
	for _, d := range diags {
		if d.Subject != nil {
			sb.WriteString(fmt.Sprintf(
				"%s:%d,%d: %s; %s",
				d.Subject.Filename,
				d.Subject.Start.Line,
				d.Subject.Start.Column,
				d.Summary,
				d.Detail,
			))
		} else {
			sb.WriteString(fmt.Sprintf("%s; %s", d.Summary, d.Detail))
		}
		sb.WriteString("\n")
	}
	return strings.TrimSpace(sb.String())
}
