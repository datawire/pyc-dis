package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/datawire/dlib/derror"
)

func main() {
	if err := Disassemble(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", os.Args[0], err)
		os.Exit(1)
	}
}

func read_u32le(in io.Reader) uint32 {
	var ret uint32
	if err := binary.Read(in, binary.LittleEndian, &ret); err != nil {
		panic(err)
	}
	return ret
}

func read_u64le(in io.Reader) uint64 {
	var ret uint64
	if err := binary.Read(in, binary.LittleEndian, &ret); err != nil {
		panic(err)
	}
	return ret
}

func read_i32le(in io.Reader) int32 {
	var ret int32
	if err := binary.Read(in, binary.LittleEndian, &ret); err != nil {
		panic(err)
	}
	return ret
}

func read_i64le(in io.Reader) int64 {
	var ret int64
	if err := binary.Read(in, binary.LittleEndian, &ret); err != nil {
		panic(err)
	}
	return ret
}

func read_byte(in io.Reader) uint8 {
	var ret [1]byte
	if _, err := io.ReadFull(in, ret[:]); err != nil {
		panic(err)
	}
	return ret[0]
}

// The reverse of `Lib/importlib/_bootstrap_external.py`
// _code_to_timestamp_pyc() and _code_to_hash_pyc().
func Disassemble(in io.Reader, out io.Writer) (err error) {
	defer func() {
		if _err := derror.PanicToError(recover()); _err != nil {
			err = _err
		}
	}()

	fmt.Fprintf(out, "(4) magic    = %#08x\n", read_u32le(in))

	flags := read_u32le(in)
	fmt.Fprintf(out, "(4) flags    = %#032b\n", flags)
	fmt.Fprintf(out, "             :   [          undefined         ][]\n")
	fmt.Fprintf(out, "             :                                 ^invalidation mode\n")
	switch flags & 0b11 {
	case 0b00:
		fmt.Fprintf(out, "             : invalidation_mode=TIMESTAMP\n")
		mtime := read_u32le(in)
		fmt.Fprintf(out, "(4) src_mtime= %d (%v)\n", mtime, time.Unix(int64(mtime), 0))
		fmt.Fprintf(out, "(4) src_size = %d\n", read_u32le(in))
	case 0b01:
		fmt.Fprintf(out, "             : invalidation_mode=UNCHECKED_HASH\n")
		var hash [8]byte
		if _, err := io.ReadFull(in, hash[:]); err != nil {
			return err
		}
		fmt.Fprintf(out, "(8) src_hash = %s\n", hex.EncodeToString(hash[:]))
	case 0b11:
		fmt.Fprintf(out, "             : invalidation_mode=CHECKED_HASH\n")
		var hash [8]byte
		if _, err := io.ReadFull(in, hash[:]); err != nil {
			return err
		}
		fmt.Fprintf(out, "(8) src_hash = %s\n", hex.EncodeToString(hash[:]))
	case 0b10:
		fmt.Fprintf(out, "             : invalidation_mode=INVALID\n")
		var data [8]byte
		if _, err := io.ReadFull(in, data[:]); err != nil {
			return err
		}
		fmt.Fprintf(out, "(8) ???????? = 0x%s\n", hex.EncodeToString(data[:]))
	}

	fmt.Fprintf(out, "    code     =\n")
	p := &rFile{
		in: in,
	}
	_ = p.rObject("             : ", out)

	return nil
}

var typ2name = map[uint8]string{
	'0': "TYPE_NULL",
	'N': "TYPE_NONE",
	'F': "TYPE_FALSE",
	'T': "TYPE_TRUE",
	'S': "TYPE_STOPITER",
	'.': "TYPE_ELLIPSIS",
	'i': "TYPE_INT",
	'I': "TYPE_INT64",
	'f': "TYPE_FLOAT",
	'g': "TYPE_BINARY_FLOAT",
	'x': "TYPE_COMPLEX",
	'y': "TYPE_BINARY_COMPLEX",
	'l': "TYPE_LONG",
	's': "TYPE_STRING",
	't': "TYPE_INTERNED",
	'r': "TYPE_REF",
	'(': "TYPE_TUPLE",
	'[': "TYPE_LIST",
	'{': "TYPE_DICT",
	'c': "TYPE_CODE",
	'u': "TYPE_UNICODE",
	'?': "TYPE_UNKNOWN",
	'<': "TYPE_SET",
	'>': "TYPE_FROZENSET",

	//0x80: "FLAG_REF",

	'a': "TYPE_ASCII",
	'A': "TYPE_ASCII_INTERNED",
	')': "TYPE_SMALL_TUPLE",
	'z': "TYPE_SHORT_ASCII",
	'Z': "TYPE_SHORT_ASCII_INTERNED",
}

const (
	TYPE_NULL           = '0'
	TYPE_NONE           = 'N'
	TYPE_FALSE          = 'F'
	TYPE_TRUE           = 'T'
	TYPE_STOPITER       = 'S'
	TYPE_ELLIPSIS       = '.'
	TYPE_INT            = 'i'
	TYPE_INT64          = 'I'
	TYPE_FLOAT          = 'f'
	TYPE_BINARY_FLOAT   = 'g'
	TYPE_COMPLEX        = 'x'
	TYPE_BINARY_COMPLEX = 'y'
	TYPE_LONG           = 'l'
	TYPE_STRING         = 's'
	TYPE_INTERNED       = 't'
	TYPE_REF            = 'r'
	TYPE_TUPLE          = '('
	TYPE_LIST           = '['
	TYPE_DICT           = '{'
	TYPE_CODE           = 'c'
	TYPE_UNICODE        = 'u'
	TYPE_UNKNOWN        = '?'
	TYPE_SET            = '<'
	TYPE_FROZENSET      = '>'

	FLAG_REF = 0x80

	TYPE_ASCII                = 'a'
	TYPE_ASCII_INTERNED       = 'A'
	TYPE_SMALL_TUPLE          = ')'
	TYPE_SHORT_ASCII          = 'z'
	TYPE_SHORT_ASCII_INTERNED = 'Z'
)

type PyConst int

const (
	PyNone PyConst = iota
	PyStopIteration
	PyEllipsis
	PyFalse
	PyTrue
)

type (
	PyTuple     []interface{}
	PySet       map[interface{}]struct{}
	PyFrozenSet map[interface{}]struct{}
)

type PyCode struct {
	NArgs, NPosArgs, NKwArgs int32
	NLocals                  int32
	StackSize                int32
	Flags                    int32
	Code                     interface{}
	Consts                   interface{}
	Names                    interface{}
	VarNames                 interface{}
	FreeVars                 interface{}
	CellVars                 interface{}
	Filename                 interface{}
	Name                     interface{}
	FirstLineNo              int32
	LNoTab                   interface{}
}

type rFile struct {
	in   io.Reader
	refs []interface{}
}

func (p *rFile) rFloatStr(indent string, out io.Writer) (string, float64) {
	n := read_byte(p.in)
	fmt.Fprintf(out, "%s(1)   flen = %d\n", indent, n)
	buf := make([]byte, n)
	if _, err := io.ReadFull(p.in, buf); err != nil {
		panic(err)
	}
	val, err := strconv.ParseFloat(string(buf), 64)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(out, "%s(% 3d) fval = %q (%v)\n", indent, n, buf, val)
	return string(buf), val
}

func (p *rFile) rFloatBin() ([8]byte, float64) {
	var buf [8]byte
	if _, err := io.ReadFull(p.in, buf[:]); err != nil {
		panic(err)
	}
	var val float64
	if err := binary.Read(bytes.NewReader(buf[:]), binary.LittleEndian, &val); err != nil {
		panic(err)
	}
	return buf, val
}

func (p *rFile) rObject(indent string, out io.Writer) interface{} {
	typ := read_byte(p.in)
	flag := (typ & FLAG_REF) != 0
	typ &^= FLAG_REF

	typName, ok := typ2name[typ]
	if !ok {
		panic(fmt.Errorf("unknown type %[1]d %[1]c", typ))
	}

	flagStr := "0"
	if flag {
		flagStr = "FLAG_REF"
	}
	fmt.Fprintf(out, "%[1]s(1) type = %[2]q (%[3]s) | %[4]s\n", indent, typ, typName, flagStr)

	rRef := func(indent string, o interface{}) interface{} {
		if flag {
			fmt.Printf("%s^^ ref#%d ^^\n", indent, len(p.refs))
			p.refs = append(p.refs, o)
		}
		return o
	}

	switch typ {
	case TYPE_NULL:
		// do nothing
		return nil
	case TYPE_NONE:
		fmt.Fprintf(out, "%s         : val = None\n", indent)
		return PyNone
	case TYPE_STOPITER:
		fmt.Fprintf(out, "%s         : val = StopIteration\n", indent)
		return PyStopIteration
	case TYPE_ELLIPSIS:
		fmt.Fprintf(out, "%s         : val = Ellipsis\n", indent)
		return PyEllipsis
	case TYPE_FALSE:
		fmt.Fprintf(out, "%s         : val = False\n", indent)
		return PyFalse
	case TYPE_TRUE:
		fmt.Fprintf(out, "%s         : val = True\n", indent)
		return PyTrue
	case TYPE_INT:
		val := read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) val  = %d\n", indent, val)
		rRef(indent, val)
		return val
	case TYPE_INT64:
		val := read_i64le(p.in)
		fmt.Fprintf(out, "%s(8) val  = %d\n", indent, val)
		return rRef(indent, val)
	case TYPE_FLOAT:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		_, val := p.rFloatStr(indent+sIndent, out)
		return rRef(indent, val)
	case TYPE_BINARY_FLOAT:
		buf, val := p.rFloatBin()
		fmt.Fprintf(out, "%s(8) val  = %s (%v)\n", indent, hex.EncodeToString(buf[:]), val)
		return val
	case TYPE_COMPLEX:
		fmt.Fprintf(out, "%s    real =\n", indent)
		sIndent := "         : "
		fmt.Fprintf(out, "%s    real =\n", indent)
		_, real := p.rFloatStr(indent+sIndent, out)
		fmt.Fprintf(out, "%s    imag =\n", indent)
		_, imag := p.rFloatStr(indent+sIndent, out)
		return rRef(indent, complex(real, imag))
	case TYPE_BINARY_COMPLEX:
		buf, real := p.rFloatBin()
		fmt.Fprintf(out, "%s(8) real = %s (%v)\n", indent, hex.EncodeToString(buf[:]), real)
		buf, imag := p.rFloatBin()
		fmt.Fprintf(out, "%s(8) imag = %s (%v)\n", indent, hex.EncodeToString(buf[:]), imag)
		return rRef(indent, complex(real, imag))
	case TYPE_STRING:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		n := read_i32le(p.in)
		if n < 0 {
			return fmt.Errorf("bad marshal data: bytes object size out of range: %d", n)
		}
		fmt.Fprintf(out, "%s(4)     slen = %d\n", indent+sIndent, n)
		buf := make([]byte, n)
		if _, err := io.ReadFull(p.in, buf); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s%-8ssval = %q\n", indent+sIndent, fmt.Sprintf("(%d)", n), buf)
		return rRef(indent, buf)
	case TYPE_ASCII_INTERNED, TYPE_ASCII, TYPE_SHORT_ASCII_INTERNED, TYPE_SHORT_ASCII:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		//isInterned := (typ == TYPE_ASCII_INTERNED) || (typ == TYPE_SHORT_ASCII_INTERNED)
		var n int32
		if (typ == TYPE_ASCII) || (typ == TYPE_ASCII_INTERNED) {
			n = read_i32le(p.in)
			fmt.Fprintf(out, "%s(4)     slen = %d\n", indent+sIndent, n)
		} else {
			n = int32(read_byte(p.in))
			fmt.Fprintf(out, "%s(1)     slen = %d\n", indent+sIndent, n)
		}
		if n < 0 {
			return fmt.Errorf("bad marshal data: string object size out of range: %d", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(p.in, buf); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s%-8ssval = %q\n", indent+sIndent, fmt.Sprintf("(%d)", n), buf)
		return rRef(indent, string(buf))
	case TYPE_INTERNED, TYPE_UNICODE:
		//isInterned := (typ == TYPE_INTERNED)
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		n := read_i32le(p.in)
		fmt.Fprintf(out, "%s(4)     slen = %d\n", indent+sIndent, n)
		if n < 0 {
			return fmt.Errorf("bad marshal data: string size out of range: %d", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(p.in, buf); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s%-8ssval = %q\n", indent+sIndent, fmt.Sprintf("(%d)", n), buf)
		return rRef(indent, string(buf))
	case TYPE_TUPLE, TYPE_SMALL_TUPLE:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		var n int32
		if typ == TYPE_TUPLE {
			n = read_i32le(p.in)
			fmt.Fprintf(out, "%s(4)     tlen = %d\n", indent+sIndent, n)
		} else {
			n = int32(read_byte(p.in))
			fmt.Fprintf(out, "%s(1)     tlen = %d\n", indent+sIndent, n)
		}
		if n < 0 {
			return fmt.Errorf("bad marshal data: tuple size out of range: %d", n)
		}
		ret := make(PyTuple, n)
		tIndent := sIndent + "             : "
		for i := range ret {
			fmt.Fprintf(out, "%s% 12s =\n", indent+sIndent, fmt.Sprintf("tval[%d]", i))
			ret[i] = p.rObject(indent+tIndent, out)
		}
		return rRef(indent, ret)
	case TYPE_LIST:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         = "
		n := read_i32le(p.in)
		fmt.Fprintf(out, "%s(4)     llen = %d\n", indent+sIndent, n)
		if n < 0 {
			return fmt.Errorf("bad marshal data: list size out of range: %d", n)
		}
		ret := make([]interface{}, n)
		tIndent := sIndent + "             : "
		for i := range ret {
			fmt.Fprintf(out, "%s% 12s =\n", indent+sIndent, fmt.Sprintf("lval[%d]", i))
			ret[i] = p.rObject(indent+tIndent, out)
		}
		return rRef(indent, ret)
	case TYPE_DICT:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		// NULL-terminated
		ret := make(map[interface{}]interface{})
		_ = rRef(indent, ret)
		i := 0
		tIndent := sIndent + "             : "
		for {
			fmt.Fprintf(out, "%s% 12s =\n", indent+sIndent, fmt.Sprintf("dkey[%d]", i))
			k := p.rObject(indent+tIndent, out)
			if k == nil {
				return ret
			}
			fmt.Fprintf(out, "%s% 12s =\n", indent+sIndent, fmt.Sprintf("dval[%d]", i))
			v := p.rObject(indent+tIndent, out)
			ret[k] = v
		}
	case TYPE_SET, TYPE_FROZENSET:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		n := read_i32le(p.in)
		fmt.Fprintf(out, "%s(4)     slen = %d\n", indent+sIndent, n)
		if n < 0 {
			return fmt.Errorf("bad marshal data: set size out of range: %d", n)
		}
		ret := make(PySet, n)
		if typ == TYPE_SET {
			_ = rRef(indent, ret)
		} else {
			_ = rRef(indent, PyFrozenSet(ret))
		}
		tIndent := sIndent + "             : "
		for i := int32(0); i < n; i++ {
			fmt.Fprintf(out, "%s% 12s =\n", indent+sIndent, fmt.Sprintf("sval[%d]", i))
			v := p.rObject(indent+tIndent, out)
			ret[v] = struct{}{}
		}
		if typ == TYPE_FROZENSET {
			return PyFrozenSet(ret)
		}
		return ret
	case TYPE_CODE:
		fmt.Fprintf(out, "%s    val  =\n", indent)
		sIndent := "         : "
		val := &PyCode{}
		_ = rRef(indent, val)

		val.NArgs = read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) nArg      = %d\n", indent+sIndent, val.NArgs)
		tIndent := sIndent + "              : "

		val.NPosArgs = read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) nPosArg   = %d\n", indent+sIndent, val.NPosArgs)

		val.NKwArgs = read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) nKwArg    = %d\n", indent+sIndent, val.NKwArgs)

		val.NLocals = read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) nLocals   = %d\n", indent+sIndent, val.NLocals)

		val.StackSize = read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) stackSize = %d\n", indent+sIndent, val.StackSize)

		val.Flags = read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) flags     = %#08x\n", indent+sIndent, val.Flags)

		fmt.Fprintf(out, "%s    code      =\n", indent+sIndent)
		val.Code = p.rObject(indent+tIndent, out)

		fmt.Fprintf(out, "%s    consts    =\n", indent+sIndent)
		val.Consts = p.rObject(indent+tIndent, out)

		fmt.Fprintf(out, "%s    names     =\n", indent+sIndent)
		val.Names = p.rObject(indent+tIndent, out)

		fmt.Fprintf(out, "%s    varnames  =\n", indent+sIndent)
		val.VarNames = p.rObject(indent+tIndent, out)

		fmt.Fprintf(out, "%s    freevars  =\n", indent+sIndent)
		val.FreeVars = p.rObject(indent+tIndent, out)

		fmt.Fprintf(out, "%s    cellvars  =\n", indent+sIndent)
		val.CellVars = p.rObject(indent+tIndent, out)

		fmt.Fprintf(out, "%s    filename  =\n", indent+sIndent)
		val.Filename = p.rObject(indent+tIndent, out)

		fmt.Fprintf(out, "%s    name      =\n", indent+sIndent)
		val.Name = p.rObject(indent+tIndent, out)

		val.FirstLineNo = read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) 1st-line  = %d\n", indent+sIndent, val.FirstLineNo)

		fmt.Fprintf(out, "%s    lNoTab    =\n", indent+sIndent)
		val.LNoTab = p.rObject(indent+tIndent, out)

		return val
	case TYPE_REF:
		n := read_i32le(p.in)
		fmt.Fprintf(out, "%s(4) ref  = %d\n", indent, n)
		if n < 0 || int(n) >= len(p.refs) {
			return fmt.Errorf("bad marshal data: invalid reference: %d", n)
		}
		return p.refs[n]
	default:
		panic("should not happen")
	}
}
