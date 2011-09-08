#!/usr/bin/env python
#
# Java class dissambler
#
# @startdate: July 18, 2002
# @enddate: July 19, 2002
#

from struct import *

# Constant pool info
CONSTANT_Class = 7
CONSTANT_Fieldref = 9
CONSTANT_Methodref = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_String = 8
CONSTANT_Integer = 3
CONSTANT_Float = 4
CONSTANT_Long = 5
CONSTANT_Double = 6 
CONSTANT_NameAndType = 12
CONSTANT_Utf8 = 1
CONSTANT_Invalid = 69

# Attribute types
CODE = 'Code'
CONSTANT_VALUE = 'ConstantValue'
EXCEPTIONS = 'Exceptions'
SPC = '          '

# Access flags:
ACC_PUBLIC          = 0x0001
ACC_PRIVATE         = 0x0002
ACC_PROTECTED       = 0x0004
ACC_STATIC          = 0x0008
ACC_FINAL           = 0x0010
ACC_SYNCHRONIZED    = 0x0020
ACC_SUPER           = 0x0020  
ACC_VOLATILE        = 0x0040
ACC_TRANSIENT       = 0x0080
ACC_NATIVE          = 0x0100
ACC_INTERFACE       = 0x0200
ACC_ABSTRACT        = 0x0400

# Types:
T_BOOLEAN      = 4
T_CHAR         = 5
T_FLOAT        = 6
T_DOUBLE       = 7
T_BYTE         = 8
T_SHORT        = 9
T_INT          = 10
T_LONG         = 11

# Bytecode instructions
NOP                 = 0x00
ACONST_NULL         = 0x01
ICONST_M1           = 0x02
ICONST_0            = 0x03
ICONST_1            = 0x04
ICONST_2            = 0x05
ICONST_3            = 0x06
ICONST_4            = 0x07
ICONST_5            = 0x08
LCONST_0            = 0x09
LCONST_1            = 0x0a
FCONST_0            = 0x0b
FCONST_1            = 0x0c
FCONST_2            = 0x0d
DCONST_0            = 0x0e
DCONST_1            = 0x0f
BIPUSH              = 0x10
SIPUSH              = 0x11
LDC                 = 0x12
LDC_W               = 0x13
LDC2_W              = 0x14
ILOAD               = 0x15
LLOAD               = 0x16
FLOAD               = 0x17
DLOAD               = 0x18
ALOAD               = 0x19
ILOAD_0             = 0x1a
ILOAD_1             = 0x1b
ILOAD_2             = 0x1c
ILOAD_3             = 0x1d
LLOAD_0             = 0x1e
LLOAD_1             = 0x1f
LLOAD_2             = 0x20
LLOAD_3             = 0x21
FLOAD_0             = 0x22
FLOAD_1             = 0x23
FLOAD_2             = 0x24
FLOAD_3             = 0x25
DLOAD_0             = 0x26
DLOAD_1             = 0x27
DLOAD_2             = 0x28
DLOAD_3             = 0x29
ALOAD_0             = 0x2a
ALOAD_1             = 0x2b
ALOAD_2             = 0x2c
ALOAD_3             = 0x2d
IALOAD              = 0x2e
LALOAD              = 0x2f
FALOAD              = 0x30
DALOAD              = 0x31
AALOAD              = 0x32
BALOAD              = 0x33
CALOAD              = 0x34
SALOAD              = 0x35
ISTORE              = 0x36
LSTORE              = 0x37
FSTORE              = 0x38
DSTORE              = 0x39
ASTORE              = 0x3a
ISTORE_0            = 0x3b
ISTORE_1            = 0x3c
ISTORE_2            = 0x3d
ISTORE_3            = 0x3e
LSTORE_0            = 0x3f
LSTORE_1            = 0x40
LSTORE_2            = 0x41
LSTORE_3            = 0x42
FSTORE_0            = 0x43
FSTORE_1            = 0x44
FSTORE_2            = 0x45
FSTORE_3            = 0x46
DSTORE_0            = 0x47
DSTORE_1            = 0x48
DSTORE_2            = 0x49
DSTORE_3            = 0x4a
ASTORE_0            = 0x4b
ASTORE_1            = 0x4c
ASTORE_2            = 0x4d
ASTORE_3            = 0x4e
IASTORE             = 0x4f
LASTORE             = 0x50
FASTORE             = 0x51
DASTORE             = 0x52
AASTORE             = 0x53
BASTORE             = 0x54
CASTORE             = 0x55
SASTORE             = 0x56
POP                 = 0x57
POP2                = 0x58
DUP                 = 0x59
DUP_X1              = 0x5a
DUP_X2              = 0x5b
DUP2                = 0x5c
DUP2_X1             = 0x5d
DUP2_X2             = 0x5e
SWAP                = 0x5f
IADD                = 0x60
LADD                = 0x61
FADD                = 0x62
DADD                = 0x63
ISUB                = 0x64
LSUB                = 0x65
FSUB                = 0x66
DSUB                = 0x67
IMUL                = 0x68
LMUL                = 0x69
FMUL                = 0x6a
DMUL                = 0x6b
IDIV                = 0x6c
LDIV                = 0x6d
FDIV                = 0x6e
DDIV                = 0x6f
IREM                = 0x70
LREM                = 0x71
FREM                = 0x72
DREM                = 0x73
INEG                = 0x74
LNEG                = 0x75
FNEG                = 0x76
DNEG                = 0x77
ISHL                = 0x78
LSHL                = 0x79
ISHR                = 0x7a
LSHR                = 0x7b
IUSHR               = 0x7c
LUSHR               = 0x7d
IAND                = 0x7e
LAND                = 0x7f
IOR                 = 0x80
LOR                 = 0x81
IXOR                = 0x82
LXOR                = 0x83
IINC                = 0x84
I2L                 = 0x85
I2F                 = 0x86
I2D                 = 0x87
L2I                 = 0x88
L2F                 = 0x89
L2D                 = 0x8a
F2I                 = 0x8b
F2L                 = 0x8c
F2D                 = 0x8d
D2I                 = 0x8e
D2L                 = 0x8f
D2F                 = 0x90
I2B                 = 0x91
I2C                 = 0x92
I2S                 = 0x93
LCMP                = 0x94
FCMPL               = 0x95
FCMPG               = 0x96
DCMPL               = 0x97
DCMPG               = 0x98
IFEQ                = 0x99
IFNE                = 0x9a
IFLT                = 0x9b
IFGE                = 0x9c
IFGT                = 0x9d
IFLE                = 0x9e
IF_ICMPEQ           = 0x9f
IF_ICMPNE           = 0xa0
IF_ICMPLT           = 0xa1
IF_ICMPGE           = 0xa2
IF_ICMPGT           = 0xa3
IF_ICMPLE           = 0xa4
IF_ACMPEQ           = 0xa5
IF_ACMPNE           = 0xa6
GOTO                = 0xa7
JSR                 = 0xa8
RET                 = 0xa9
TABLESWITCH         = 0xaa
LOOKUPSWITCH        = 0xab
IRETURN             = 0xac
LRETURN             = 0xad
FRETURN             = 0xae
DRETURN             = 0xaf
ARETURN             = 0xb0
RETURN              = 0xb1
GETSTATIC           = 0xb2
PUTSTATIC           = 0xb3
GETFIELD            = 0xb4
PUTFIELD            = 0xb5
INVOKEVIRTUAL       = 0xb6
INVOKESPECIAL       = 0xb7
INVOKESTATIC        = 0xb8
INVOKEINTERFACE     = 0xb9
XXXUNUSEDXXX        = 0xba
NEW                 = 0xbb
NEWARRAY            = 0xbc
ANEWARRAY           = 0xbd
ARRAYLENGTH         = 0xbe
ATHROW              = 0xbf
CHECKCAST           = 0xc0
INSTANCEOF          = 0xc1
MONITORENTER        = 0xc2
MONITOREXIT         = 0xc3
WIDE                = 0xc4
MULTIANEWARRAY      = 0xc5
IFNULL              = 0xc6
IFNONNULL           = 0xc7
GOTO_W              = 0xc8
JSR_W               = 0xc9

bytecodedict = {
    NOP : 'NOP',
    ACONST_NULL : 'ACONST_NULL',
    ICONST_M1 : 'ICONST_M1',
    ICONST_0 : 'ICONST_0',
    ICONST_1 : 'ICONST_1',
    ICONST_2 : 'ICONST_2',
    ICONST_3 : 'ICONST_3',
    ICONST_4 : 'ICONST_4',
    ICONST_5 : 'ICONST_5',
    LCONST_0 : 'LCONST_0',
    LCONST_1 : 'LCONST_1',
    FCONST_0 : 'FCONST_0',
    FCONST_1 : 'FCONST_1',
    FCONST_2 : 'FCONST_2',
    DCONST_0 : 'DCONST_0',
    DCONST_1 : 'DCONST_1',
    BIPUSH : 'BIPUSH',
    SIPUSH : 'SIPUSH',
    LDC : 'LDC',
    LDC_W : 'LDC_W',
    LDC2_W : 'LDC2_W',
    ILOAD : 'ILOAD',
    LLOAD : 'LLOAD',
    FLOAD : 'FLOAD',
    DLOAD : 'DLOAD',
    ALOAD : 'ALOAD',
    ILOAD_0 : 'ILOAD_0',
    ILOAD_1 : 'ILOAD_1',
    ILOAD_2 : 'ILOAD_2',
    ILOAD_3 : 'ILOAD_3',
    LLOAD_0 : 'LLOAD_0',
    LLOAD_1 : 'LLOAD_1',
    LLOAD_2 : 'LLOAD_2',
    LLOAD_3 : 'LLOAD_3',
    FLOAD_0 : 'FLOAD_0',
    FLOAD_1 : 'FLOAD_1',
    FLOAD_2 : 'FLOAD_2',
    FLOAD_3 : 'FLOAD_3',
    DLOAD_0 : 'DLOAD_0',
    DLOAD_1 : 'DLOAD_1',
    DLOAD_2 : 'DLOAD_2',
    DLOAD_3 : 'DLOAD_3',
    ALOAD_0 : 'ALOAD_0',
    ALOAD_1 : 'ALOAD_1',
    ALOAD_2 : 'ALOAD_2',
    ALOAD_3 : 'ALOAD_3',
    IALOAD : 'IALOAD',
    LALOAD : 'LALOAD',
    FALOAD : 'FALOAD',
    DALOAD : 'DALOAD',
    AALOAD : 'AALOAD',
    BALOAD : 'BALOAD',
    CALOAD : 'CALOAD',
    SALOAD : 'SALOAD',
    ISTORE : 'ISTORE',
    LSTORE : 'LSTORE',
    FSTORE : 'FSTORE',
    DSTORE : 'DSTORE',
    ASTORE : 'ASTORE',
    ISTORE_0 : 'ISTORE_0',
    ISTORE_1 : 'ISTORE_1',
    ISTORE_2 : 'ISTORE_2',
    ISTORE_3 : 'ISTORE_3',
    LSTORE_0 : 'LSTORE_0',
    LSTORE_1 : 'LSTORE_1',
    LSTORE_2 : 'LSTORE_2',
    LSTORE_3 : 'LSTORE_3',
    FSTORE_0 : 'FSTORE_0',
    FSTORE_1 : 'FSTORE_1',
    FSTORE_2 : 'FSTORE_2',
    FSTORE_3 : 'FSTORE_3',
    DSTORE_0 : 'DSTORE_0',
    DSTORE_1 : 'DSTORE_1',
    DSTORE_2 : 'DSTORE_2',
    DSTORE_3 : 'DSTORE_3',
    ASTORE_0 : 'ASTORE_0',
    ASTORE_1 : 'ASTORE_1',
    ASTORE_2 : 'ASTORE_2',
    ASTORE_3 : 'ASTORE_3',
    IASTORE : 'IASTORE',
    LASTORE : 'LASTORE',
    FASTORE : 'FASTORE',
    DASTORE : 'DASTORE',
    AASTORE : 'AASTORE',
    BASTORE : 'BASTORE',
    CASTORE : 'CASTORE',
    SASTORE : 'SASTORE',
    POP : 'POP',
    POP2 : 'POP2',
    DUP : 'DUP',
    DUP_X1 : 'DUP_X1',
    DUP_X2 : 'DUP_X2',
    DUP2 : 'DUP2',
    DUP2_X1 : 'DUP2_X1',
    DUP2_X2 : 'DUP2_X2',
    SWAP : 'SWAP',
    IADD : 'IADD',
    LADD : 'LADD',
    FADD : 'FADD',
    DADD : 'DADD',
    ISUB : 'ISUB',
    LSUB : 'LSUB',
    FSUB : 'FSUB',
    DSUB : 'DSUB',
    IMUL : 'IMUL',
    LMUL : 'LMUL',
    FMUL : 'FMUL',
    DMUL : 'DMUL',
    IDIV : 'IDIV',
    LDIV : 'LDIV',
    FDIV : 'FDIV',
    DDIV : 'DDIV',
    IREM : 'IREM',
    LREM : 'LREM',
    FREM : 'FREM',
    DREM : 'DREM',
    INEG : 'INEG',
    LNEG : 'LNEG',
    FNEG : 'FNEG',
    DNEG : 'DNEG',
    ISHL : 'ISHL',
    LSHL : 'LSHL',
    ISHR : 'ISHR',
    LSHR : 'LSHR',
    IUSHR :'IUSHR',
    LUSHR :'LUSHR',
    IAND : 'IAND',
    LAND : 'LAND',
    IOR : 'IOR',
    LOR : 'LOR',
    IXOR : 'IXOR',
    LXOR : 'LXOR',
    IINC : 'IINC',
    I2L : 'I2L',
    I2F : 'I2F',
    I2D : 'I2D',
    L2I : 'L2I',
    L2F : 'L2F',
    L2D : 'L2D',
    F2I : 'F2I',
    F2L : 'F2L',
    F2D : 'F2D',
    D2I : 'D2I',
    D2L : 'D2L',
    D2F : 'D2F',
    I2B : 'I2B',
    I2C : 'I2C',
    I2S : 'I2S',
    LCMP : 'LCMP',
    FCMPL : 'FCMPL',
    FCMPG : 'FCMPG',
    DCMPL : 'DCMPL',
    DCMPG : 'DCMPG',
    IFEQ : 'IFEQ',
    IFNE : 'IFNE',
    IFLT : 'IFLT',
    IFGE : 'IFGE',
    IFGT : 'IFGT',
    IFLE : 'IFLE',
    IF_ICMPEQ : 'IF_ICMPEQ',
    IF_ICMPNE : 'IF_ICMPNE',
    IF_ICMPLT : 'IF_ICMPLT',
    IF_ICMPGE : 'IF_ICMPGE',
    IF_ICMPGT : 'IF_ICMPGT',
    IF_ICMPLE : 'IF_ICMPLE',
    IF_ACMPEQ : 'IF_ACMPEQ',
    IF_ACMPNE : 'IF_ACMPNE',
    GOTO : 'GOTO',
    JSR : 'JSR',
    RET : 'RET',
    TABLESWITCH : 'TABLESWITCH',
    LOOKUPSWITCH : 'LOOKUPSWITCH',
    IRETURN : 'IRETURN',
    LRETURN : 'LRETURN',
    FRETURN : 'FRETURN',
    DRETURN : 'DRETURN',
    ARETURN : 'ARETURN',
    RETURN : 'RETURN',
    GETSTATIC : 'GETSTATIC',
    PUTSTATIC : 'PUTSTATIC',
    GETFIELD : 'GETFIELD',
    PUTFIELD : 'PUTFIELD',
    INVOKEVIRTUAL : 'INVOKEVIRTUAL',
    INVOKESPECIAL : 'INVOKESPECIAL',
    INVOKESTATIC : 'INVOKESTATIC',
    INVOKEINTERFACE : 'INVOKEINTERFACE',
    XXXUNUSEDXXX : 'XXXUNUSEDXXX',
    NEW : 'NEW',
    NEWARRAY : 'NEWARRAY',
    ANEWARRAY : 'ANEWARRAY',
    ARRAYLENGTH : 'ARRAYLENGTH',
    ATHROW : 'ATHROW',
    CHECKCAST : 'CHECKCAST',
    INSTANCEOF : 'INSTANCEOF',
    MONITORENTER : 'MONITORENTER',
    MONITOREXIT : 'MONITOREXIT',
    WIDE : 'WIDE',
    MULTIANEWARRAY : 'MULTIANEWARRAY',
    IFNULL : 'IFNULL',
    IFNONNULL : 'IFNONNULL',
    GOTO_W : 'GOTO_W',
    JSR_W : 'JSR_W'
}

typesdict = {
    T_BOOLEAN : 'T_BOOLEAN',
    T_CHAR : 'T_CHAR',
    T_FLOAT : 'T_FLOAT',
    T_DOUBLE : 'T_DOUBLE',
    T_BYTE : 'T_BYTE', 
    T_SHORT : 'T_SHORT',
    T_INT : 'T_INT', 
    T_LONG : 'T_LONG', 
}    

flagdict = {
    ACC_PUBLIC:'ACCESS_PUBLIC',
    ACC_PRIVATE:'ACCESS_PRIVATE',
    ACC_PROTECTED:'ACCESS_PROTECTED',
    ACC_STATIC:'ACCESS_STATIC',
    ACC_FINAL:'ACCESS_FINAL',
    ACC_SYNCHRONIZED:'ACCESS_SYNCHRONIZED',
    ACC_SUPER:'ACCESS_SUPER',
    ACC_VOLATILE:'ACCESS_VOLATILE',
    ACC_TRANSIENT:'ACCESS_TRANSIENT',
    ACC_NATIVE:'ACCESS_NATIVE', 
    ACC_INTERFACE:'ACCESS_INTERFACE',
    ACC_ABSTRACT:'ACCESS_ABSTRACT'
}

# class Classreader
class Classreader:
    def __init__(self, filename):
        self.file = filename
        self.idx = 0        
        
    def __readclass__(self):
        try:
            fd = open(self.file, 'rb')
        except IOError:
            errorandexit('Cannot open binary file ' + self.file)

        lines = fd.readlines()
        str = ''
        for line in lines:
            str = str + line

        cf = Classfile()

        # Read in headers
        cf.magic = self.__readu4__(str)
        cf.minorversion = self.__readu2__(str)
        cf.majorversion = self.__readu2__(str)

        # Read the const pool
        cf.cpcount = self.__readu2__(str)
        cf.cpinfo.append(None)

        for i in range(cf.cpcount-1):
            cpinfo = self.__readcpinfo__(str)
            cf.cpinfo.append(cpinfo)

        cf.accessflags = self.__readu2__(str)
        cf.thisclass = self.__readu2__(str)
        cf.superclass = self.__readu2__(str)

        # Read the interfaces
        cf.ifcount = self.__readu2__(str)
        for i in range(cf.ifcount):
            intf = self.__readu2__(str)
            cf.interfaces.append(intf)

        # Read the fields
        cf.fieldcount = self.__readu2__(str)
        for i in range(cf.fieldcount):
            field = self.__readfieldinfo__(str, cf)
            cf.fields.append(field)
            
        # Read the methods
        cf.methodcount = self.__readu2__(str)
        for i in range(cf.methodcount):
            method = self.__readmethodinfo__(str, cf)
            cf.methods.append(method)

        # Read the attributes
        cf.attrcount = self.__readu2__(str)
        i = 0
        while i < cf.attrcount:
            attrinfo = self.__readattributeinfo__(str, cf)
            if attrinfo == None:
                i = i - 1
                cf.attrcount = cf.attrcount - 1
            else:
                cf.attributes.append(attrinfo)
                
            i = i + 1

        return cf
        
    def __readmethodinfo__(self, str, cf):
        mi = Method()
        
        mi.accessflags = self.__readu2__(str)
        mi.nameindex = self.__readu2__(str)
        mi.descriptorindex = self.__readu2__(str)
        
        mi.attrcount = self.__readu2__(str)

        i = 0
        while i < mi.attrcount:
            attrinfo = self.__readattributeinfo__(str, cf)
            if attrinfo == None:
                i = i - 1
                mi.attrcount = mi.attrcount - 1
            else:
                mi.attributes.append(attrinfo)
                
            i = i + 1
                
        return mi

    def __readfieldinfo__(self, str, cf):
        fi = Field()

        fi.accessflags = self.__readu2__(str)
        fi.nameindex = self.__readu2__(str)
        fi.descriptorindex = self.__readu2__(str)

        fi.attrcount = self.__readu2__(str)

        i = 0
        while i < fi.attrcount:
            attrinfo = self.__readattributeinfo__(str, cf)
            if attrinfo == None:
                i = i - 1
                fi.attrcount = fi.attrcount - 1
            else:
                fi.attributes.append(attrinfo)

            i = i + 1
            
        return fi

    def __readattributeinfo__(self, str, cf):
        attnameidx = self.__readu2__(str)

        cutf8 = cf.cpinfo[attnameidx]

        if self.__utf8ncmp__(cutf8.bytes, CODE, cutf8.length) == 1:
            codei = Codeattr()
            codei.attrnameindex = attnameidx
            codei.attrlength = self.__readu4__(str)
            codei.maxstack = self.__readu2__(str)
            codei.maxlocals = self.__readu2__(str)

            # Read in the code
            codei.codelength = self.__readu4__(str)
            for i in range(codei.codelength):
                codei.code.append(self.__readu1__(str))

            # Read in exception table
            codei.etablesize = self.__readu2__(str)
            for i in range(codei.etablesize):
                e = Exception()
                e.startpc = self.__readu2__(str)
                e.endpc = self.__readu2__(str)
                e.handlerpc = self.__readu2__(str)
                e.catchtype = self.__readu2__(str)                
                codei.etable.append(e)

            # Read the attributes
            codei.attrcount = self.__readu2__(str)
            i = 0
            while i < codei.attrcount:
                attr = self.__readattributeinfo__(str, cf)
                if attr == None:
                    i = i - 1
                    codei.attrcount = codei.attrcount - 1
                else:
                    codei.attributes.append(attr)
                i = i + 1

            return codei
        else:
            len = self.__readu4__(str)
            for i in range(len):
                self.__readu1__(str)
                ai = None
            return ai

    def __utf8ncmp__(self, str1, str2, length):
        for i in range(length):
            if chr(str1[i]) != str2[i]:
                return 0

        return 1

    def __readcpinfo__(self, str):
        tag = self.__readu1__(str)
        cp = None

        if tag == CONSTANT_Class:
            cp = Constclassinfo()
            cp.tag = tag
            cp.nameindex = self.__readu2__(str)
        elif tag == CONSTANT_Fieldref:
            cp = Constfieldref()
            cp.tag = tag
            cp.classindex = self.__readu2__(str)
            cp.nametypeindex = self.__readu2__(str)
        elif tag == CONSTANT_Methodref:
            cp = Constmethodref()
            cp.tag = tag
            cp.classindex = self.__readu2__(str)
            cp.nametypeindex = self.__readu2__(str)
        elif tag == CONSTANT_InterfaceMethodref:
            cp = Constintfmethodref()
            cp.tag = tag
            cp.classindex = self.__readu2__(str)
            cp.nametypeindex = self.__readu2__(str)
        elif tag == CONSTANT_String:
            cp = Conststring()
            cp.tag = tag
            cp.stringindex = self.__readu2__(str)
        elif tag == CONSTANT_Integer:
            cp = Constint()
            cp.tag = tag
            cp.lowbytes = self.__readu4__(str)
        elif tag == CONSTANT_Float:
            cp = Constfloat()
            cp.tag = tag
            cp.lowbytes = self.__readu4__(str)
        elif tag == CONSTANT_Long:
            cp = Constlong()
            cp.tag = tag
            cp.highbytes = self.__readu4__(str)
            cp.lowbytes = self.__readu4__(str)            
        elif tag == CONSTANT_Double:
            cp = Constdbl()
            cp.tag = tag
            cp.highbytes = self.__readu4__(str)
            cp.lowbytes = self.__readu4__(str)            
        elif tag == CONSTANT_NameAndType:
            cp = Constnametype()
            cp.tag = tag
            cp.nameindex = self.__readu2__(str)
            cp.descriptorindex = self.__readu2__(str)
        elif tag == CONSTANT_Utf8:
            cp = Constutf8()
            cp.tag = tag
            cp.length = self.__readu2__(str)
            for i in range(cp.length):
                cp.bytes.append(self.__readu1__(str))
        elif tag == CONSTANT_Invalid:
            print 'Unrecognized constant pool entry', tag
        
        return cp
        
    def __readu4__(self, str):
        retval = unpack('>I', str[self.idx:self.idx+4])
        self.idx = self.idx + 4
        return retval[0]

    def __readu2__(self, str):
        retval = unpack('>H', str[self.idx:self.idx+2])
        self.idx = self.idx + 2
        return retval[0]

    def __readu1__(self, str):
        retval = unpack('>B', str[self.idx:self.idx+1])
        self.idx = self.idx + 1
        return retval[0]

# class Classdump
class Classdump:
    def __init__(self):
        pass
    
    def dumpclass(self, cf):
        print 'Magic = ', hex(cf.magic)
        print ('Version = ' + str(cf.majorversion) + '.' + str(cf.minorversion))
        print ('Access Flags: ' + self.__dumpflags__(cf.accessflags))

        # Now dump this class
        if cf.cpinfo[cf.thisclass].tag != CONSTANT_Class:
            print 'bad: this_class'
        else:
            print ('This class: '
                   + self.__dumpconstpool__(cf, cf.thisclass))

        # Now dump super class
        if cf.cpinfo[cf.superclass].tag != CONSTANT_Class:
            print 'bad: super_class'
        else:
            print ('Super class: '
                   + self.__dumpconstpool__(cf, cf.superclass))

        # Dump interfaces
        for i in range(cf.ifcount):
            if cf.cpinfo[cf.interfaces[i]].tag != CONSTANT_Class:
                print ('bad: interfaces[' + str(i) + ']')
            else:
                print ('interfaces[' + str(i) + ']' + 
                       + self.__dumpconstpool__(cf, cf.interfaces[i]))

        # Dump fields
        print 'Fields: \n'
        for i in range(cf.fieldcount):
            print ('  fields[' + str(i) + ']:\n')
            print self.__dumpfield__(cf, cf.fields[i])

        # Dump methods
        print 'Methods: \n'
        for i in range(cf.methodcount):
            print ('  methods[' + str(i) + ']:\n')
            print self.__dumpmethod__(cf, cf.methods[i])

        # Dump attributes
        print 'Attributes:\n'
        for i in range(cf.attrcount):
            print ('  attribute[' + str(i) + ']:\n')
            print self.__dumpattribute__(cf, cf.attributes[i])

    def __dumpfield__(self, cf, fi):
        str1 = ''
        str1 = str1 + '    Access Flags: '
        str1 = str1 + self.__dumpflags__(fi.accessflags) + '\n'
        str1 = str1 + '    Name: '
        str1 = str1 + self.__dumpconstpool__(cf, fi.nameindex) + '\n'
        str1 = str1 + '    Descriptor: '
        str1 = str1 + self.__dumpconstpool__(cf, fi.descriptorindex) + '\n'
        str1 = str1 + '    Attributes: \n'
        for i in range(fi.attrcount):
            str1 = str1 + '      attribute[' + str(i) + ']: '
            str1 = str1 + self.__dumpattribute__(cf, fi.attributes[i])
            str1 = str1 + '\n'

        return str1

    def __dumpmethod__(self, cf, mi):
        str1 = ''
        str1 = str1 + '    Access Flags: '
        str1 = str1 + self.__dumpflags__(mi.accessflags) + '\n'
        str1 = str1 + '    Name: '
        str1 = str1 + self.__dumpconstpool__(cf, mi.nameindex) + '\n'
        str1 = str1 + '    Descriptor: '
        str1 = str1 + self.__dumpconstpool__(cf, mi.descriptorindex) + '\n'
        str1 = str1 + '    Attributes: \n'
        for i in range(mi.attrcount):
            str1 = str1 + '      attribute[' + str(i) + ']: '
            str1 = str1 + self.__dumpattribute__(cf, mi.attributes[i])
            str1 = str1 + '\n'

        return str1

    def __dumpattribute__(self, cf, ai):
        str1 = ''
        str1 = str1 + '(type: '
        str1 = str1 + self.__dumpconstpool__(cf, ai.attrnameindex)
        str1 = str1 + ')'

        cp = cf.cpinfo[ai.attrnameindex]
        
        if self.__utf8ncmp__(cp.bytes, CODE, cp.length) == 1:
            pc = 0
            str1 = str1 + '\n'

            while pc < ai.codelength:
                str1 = str1 + '        ' + hex(pc) + ': '
                (inc, str2) = self.__dumpinstr__(cf, ai.code, pc)
                str1 = str1 + str2 + '\n'
                pc = pc + inc

        return str1

    def __utf8ncmp__(self, str1, str2, length):
        for i in range(length):
            if chr(str1[i]) != str2[i]:
                return 0

        return 1

    def __getstr__(self, idx):
        return str(idx)

    def __makeu2__(self, x1, x2):
        return ((x1<<8)|x2)

    def __makeu4__(self, x1, x2, x3, x4):
        return ((x1<<24)|(x2<<16)|(x3<<8)|x4)
    
    def __dumpconstpool__(self, cf, idx):
        str1 = ''
        cpool = cf.cpinfo

        if idx>cf.cpcount or idx==cf.cpcount or idx==0 or idx<0:
            str1 = str1 + 'Bad idx in __dumpconstpool__(): ' + self.__getstr__(idx)  + '\n'
            return str1
        
        tag = cpool[idx].tag
        
        if tag == CONSTANT_Class:
            cp = cpool[idx]
            str1 = str1 + '(CONSTANT_Class, '
            str1 = str1 + 'name: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.nameindex)
            str = str1 + ')'
        elif tag == CONSTANT_Fieldref:
            cp = cpool[idx]
            str1 = str1 + '(CONSTANT_Fieldref, '
            str1 = str1 + 'class: '
            str = str1 + self.__dumpconstpool__(cf, cp.classindex)
            str1 = str1 + ', name_and_type: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.nametypeindex)
            str1 = str1 + ')'
        elif tag == CONSTANT_Methodref:
            cp = cpool[idx]
            str1 = str1 + '(CONSTANT_Methodref, '
            str1 = str1 + 'class: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.classindex)
            str1 = str1 + ', name_and_type: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.nametypeindex)
            str1 = str1 + ')'
        elif tag == CONSTANT_InterfaceMethodref:
            cp = cpool[idx]
            str1 = str1 + '(CONSTANT_InterfaceMethodref, '
            str1 = str1 + 'class: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.classindex)
            str1 = str1 + ', name_and_type: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.nametypeindex)
            str1 = str1 + ')'
        elif tag == CONSTANT_String:
            cp = cpool[idx]
            str1 = str1 + '(CONSTANT_String, '
            str1 = str1 + 'string: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.stringindex)
            str1 = str1 + ')'            
        elif tag == CONSTANT_Integer:
            str1 = str1 + '(CONSTANT_Integer, '
        elif tag == CONSTANT_Float:
            str1 = str1 + '(CONSTANT_Float, '
        elif tag == CONSTANT_Long:
            str1 = str1 + '(CONSTANT_Long, '
        elif tag == CONSTANT_Double:
            str1 = str1 + '(CONSTANT_Double, '
        elif tag == CONSTANT_NameAndType:
            cp = cpool[idx]
            str1 = str1 + '(CONSTANT_NameAndType, '
            str1 = str1 + 'name: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.nameindex)
            str1 = str1 + ', descriptor: '
            str1 = str1 + self.__dumpconstpool__(cf, cp.descriptorindex)
            str1 = str1 + ')'            
        elif tag == CONSTANT_Utf8:
            cp = cpool[idx] 
            str1 = str1 + '(CONSTANT_Utf8, '
            for i in range(cp.length):
                str1 = str1 + chr(cp.bytes[i])
            str1 = str1 + ')'                
        else:
            str1 = str1 + '(UNKNOWN)'

        return str1
        
    def __dumpflags__(self, flags):
        str = ''
        for flag in flagdict.keys():
            if flags & flag:
                str = str + flagdict[flag] + ' '
                
        return str

    def __dumpinstr__(self, cf, code, pc):
        str = ''
        inc = 1

        if code[pc] == NOP:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ACONST_NULL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ICONST_M1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ICONST_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ICONST_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ICONST_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ICONST_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ICONST_4:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ICONST_5:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LCONST_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LCONST_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FCONST_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FCONST_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FCONST_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DCONST_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DCONST_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == BIPUSH:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == SIPUSH:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val = self.__makeu2__(tmp1, tmp2)
            str = str + self.__getstr__(val)
            inc = inc + 2            
        elif code[pc] == LDC:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == LDC_W:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val = self.__makeu2__(tmp1, tmp2)
            str = str + self.__getstr__(val)
            inc = inc + 2                        
        elif code[pc] == LDC2_W:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val = self.__makeu2__(tmp1, tmp2)
            str = str + self.__getstr__(val)
            inc = inc + 2            
        elif code[pc] == ILOAD:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == LLOAD:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == FLOAD:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == DLOAD:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == ALOAD:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == ILOAD_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ILOAD_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ILOAD_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ILOAD_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LLOAD_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LLOAD_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LLOAD_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LLOAD_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FLOAD_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FLOAD_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FLOAD_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FLOAD_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DLOAD_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DLOAD_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DLOAD_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DLOAD_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ALOAD_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ALOAD_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ALOAD_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ALOAD_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == AALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == BALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == CALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == SALOAD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ISTORE:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == LSTORE:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == FSTORE:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == DSTORE:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == ASTORE:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1            
        elif code[pc] == ISTORE_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ISTORE_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ISTORE_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ISTORE_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LSTORE_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LSTORE_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LSTORE_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LSTORE_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FSTORE_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FSTORE_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FSTORE_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FSTORE_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DSTORE_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DSTORE_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DSTORE_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DSTORE_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ASTORE_0:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ASTORE_1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ASTORE_2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ASTORE_3:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == AASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == BASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == CASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == SASTORE:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == POP:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == POP2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DUP:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DUP_X1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DUP_X2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DUP2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DUP2_X1:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DUP2_X2:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == SWAP:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IADD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LADD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FADD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DADD:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ISUB:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LSUB:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FSUB:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DSUB:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IMUL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LMUL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FMUL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DMUL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IDIV:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LDIV:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FDIV:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DDIV:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IREM:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LREM:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FREM:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DREM:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == INEG:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LNEG:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FNEG:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DNEG:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ISHL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LSHL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ISHR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LSHR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IUSHR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LUSHR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IAND:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LAND:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IOR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LOR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IXOR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LXOR:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IINC:
            str = str + bytecodedict[code[pc]]
            str = str + '[' + self.__getstr__(int(code[pc+1])) + '] +=' + self.__getstr__(int(code[pc+1]))
            inc = inc + 2
        elif code[pc] == I2L:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == I2F:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == I2D:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == L2I:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == L2F:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == L2D:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == F2I:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == F2L:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == F2D:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == D2I:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == D2L:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == D2F:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == I2B:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == I2C:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == I2S:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LCMP:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FCMPL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FCMPG:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DCMPL:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DCMPG:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == IFEQ:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IFNE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2            
        elif code[pc] == IFLT:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IFGE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IFGT:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IFLE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ICMPEQ:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ICMPNE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ICMPLT:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ICMPGE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ICMPGT:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ICMPLE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ACMPEQ:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == IF_ACMPNE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == GOTO:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == JSR:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2
        elif code[pc] == RET:
            str = str + bytecodedict[code[pc]] + SPC
            str = str + self.__getstr__(int(code[pc+1]))
            inc = inc + 1
        elif code[pc] == TABLESWITCH:
            str = str + bytecodedict[code[pc]] + SPC

            # Skip the 0-3 byte offset. The next interesting byte
            # is after that(multiple of 4)
            if pc % 4 != 0:
                offset = 4 - (pc%4)
                pc = pc + offset
                inc = inc + offset

            # Skip next word
            pc = pc + 4
            inc = inc + 4

            # Get the 'lo' part(next word)
            x1 = code[pc] 
            x1 = code[pc+1]
            x1 = code[pc+2]
            x1 = code[pc+3]
            lo = self.__makeu4__(x1, x2, x3, x4)

            # Get the 'hi' part(next word)
            x1 = code[pc+4] 
            x1 = code[pc+5]
            x1 = code[pc+6]
            x1 = code[pc+7]
            lo = self.__makeu4__(x1, x2, x3, x4)

            pc = pc + 8
            inc = inc + 8

            # Num offsets = hi-lo+1. Skip them
            skipbytes = 4 * (hi-lo+1)
            pc = pc + skipbytes
            inc = inc + skipbytes

            str = str + 'jump offsets: ' + self.__getstr__(hi-lo+1)
                
        elif code[pc] == LOOKUPSWITCH:
            str = str + bytecodedict[code[pc]] + SPC
            # Skip the 0-3 byte offset. The next interesting byte
            # is after that(multiple of 4)
            if pc % 4 != 0:
                offset = 4 - (pc%4)
                pc = pc + offset
                inc = inc + offset

            # Skip next word
            pc = pc + 4
            inc = inc + 4

            # Get the 'npairs'
            x1 = code[pc] 
            x1 = code[pc+1]
            x1 = code[pc+2]
            x1 = code[pc+3]
            npairs = self.__makeu4__(x1, x2, x3, x4)

            pc = pc + 8
            inc = inc + 8

            # offset = 2 word pairs of npairs
            skipbytes = 8 * npairs
            pc = pc + skipbytes
            inc = inc + skipbytes

            str = str + 'npairs: ' + self.__getstr__(npairs)
                
        elif code[pc] == IRETURN:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == LRETURN:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == FRETURN:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == DRETURN:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ARETURN:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == RETURN:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == GETSTATIC:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Fieldref:
                print 'Bad GETSTATIC operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2
            
        elif code[pc] == PUTSTATIC:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Fieldref:
                print 'Bad PUTSTATIC operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2

        elif code[pc] == GETFIELD:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Fieldref:
                print 'Bad GETFIELD operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2

        elif code[pc] == PUTFIELD:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Fieldref:
                print 'Bad PUTFIELD operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2
            
        elif code[pc] == INVOKEVIRTUAL:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Methodref:
                print 'Bad INVOKEVIRTUAL operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2
            
        elif code[pc] == INVOKESPECIAL:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Methodref:
                print 'Bad INVOKESPECIAL operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2
            
        elif code[pc] == INVOKESTATIC:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Methodref:
                print 'Bad INVOKESTATIC operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2
            
        elif code[pc] == INVOKEINTERFACE:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_InterfaceMethodref:
                print 'Bad INVOKEINTERFACE operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.classindex)
                str = str + ' :: '
                str = str + self.__dumpconstpool__(cf, cp.nametypeindex)

            inc = inc + 2
            
        elif code[pc] == NEW:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Class:
                print 'Bad NEW operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.nameindex)

            inc = inc + 2

        elif code[pc] == NEWARRAY:
            str = str + bytecodedict[code[pc]] + SPC

            for type in typesdict.keys():
                if code[pc+1] == type:
                    str = str + typesdict[type]

            if code[pc+1] not in typesdict.keys():
                str = str + 'BAD NEWARRAY operand'

            inc = inc + 1
            
        elif code[pc] == ANEWARRAY:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Class:
                print 'Bad ANEWARRAY operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.nameindex)

            inc = inc + 2

        elif code[pc] == ARRAYLENGTH:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == ATHROW:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == CHECKCAST:
            str = str + bytecodedict[code[pc]]
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Class:
                print 'Bad CHECKCAST operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.nameindex)

            inc = inc + 2

        elif code[pc] == INSTANCEOF:
            str = str + bytecodedict[code[pc]]
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Class:
                print 'Bad INSTANCEOF operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.nameindex)

            inc = inc + 2

        elif code[pc] == MONITORENTER:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == MONITOREXIT:
            str = str + bytecodedict[code[pc]]
        elif code[pc] == WIDE:
            # Dont know what to do you
            str = str + bytecodedict[code[pc]] + '????????'
            if code[pc+1] == IINC:
                inc = inc + 4
            else:
                inc = inc + 2
                
        elif code[pc] == MULTIANEWARRAY:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            idx = self.__makeu2__(tmp1, tmp2)
            if cf.cpinfo[idx].tag != CONSTANT_Class:
                print 'Bad MULTIANEWARRAY operands'
            else:
                cp = cf.cpinfo[idx]
                str = str + self.__dumpconstpool__(cf, cp.nameindex)
                str = str + ' : dim = ' + self.__getstr__(code[pc+3])

            inc = inc + 3
            
        elif code[pc] == IFNULL:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 3
            str = str + self.__getifinststr__(val1, val2)            
            inc = inc + 2
            
        elif code[pc] == IFNONNULL:
            str = str + bytecodedict[code[pc]] + SPC
            tmp1 = code[pc+1]
            tmp2 = code[pc+2]
            val1 = self.__makeu2__(tmp1, tmp2)
            val2 = val1 + pc - 5
            str = str + self.__getifinststr__(val1, val2)
            inc = inc + 2

        elif code[pc] == GOTO_W:
            str = str + bytecodedict[code[pc]]
            x1 = code[pc+1]
            x2 = code[pc+2]
            x3 = code[pc+3]
            x4 = code[pc+4]            
            val1 = self.__makeu4__(x1, x2, x3, x4)
            val2 = pc - 5
            str = str + self.__getifinststr__(val1, val2)       

            inc = inc + 4
            
        elif code[pc] == JSR_W:
            str = str + 'GOTO_W'
            x1 = code[pc+1]
            x2 = code[pc+2]
            x3 = code[pc+3]
            x4 = code[pc+4]            
            val1 = self.__makeu4__(x1, x2, x3, x4)
            val2 = pc - 5
            str = str + self.__getifinststr__(val1, val2)       

            inc = inc + 4

        else:
            str = str + 'UNRECOGNIZED BYTECODE INSTRUCTION: ' + hex(code[pc])

        return (inc, str)

    def __getifinststr__(self, val1, val2):
        str1 = ''
        str1 = str1 + self.__getstr__(hex(val1)) + ' (to: ' + self.__getstr__(hex(val2)) + ')'
        return str1

# class Classfile        
class Classfile:
    def __init__(self):
        self.magic = 0
        self.minorversion = 0
        self.majorversion = 0
        self.cpcount = 0
        self.cpinfo = []
        self.accessflags = 0
        self.thisclass = 0
        self.superclass = 0
        self.ifcount = 0
        self.interfaces = []
        self.fieldcount = 0
        self.fields = []
        self.methodcount = 0
        self.methods = []
        self.attrcount = 0
        self.attributes = []

# class Cpinfo
class Cpinfo:
    def __init__(self):
        self.tag = 0
        self.info = None


# class Constinfo
class Constinfo:
    def __init__(self):
        self.tag = 0
        self.classindex = 0
        self.nametypeindex = 0

# class Constclass
class Constclassinfo:
    def __init__(self):
        self.tag = 0
        self.nameindex = 0

# class Constfieldref
class Constfieldref(Constinfo):
    def __init__(self):
        Constinfo.__init__(self)

# class Constmethodref
class Constmethodref(Constinfo):
    def __init__(self):
        Constinfo.__init__(self)        

# class Constintfmethodref
class Constintfmethodref(Constinfo):
    def __init__(self):
        Constinfo.__init__(self)

# class Conststring
class Conststring:
    def __init__(self):
        self.tag = 0
        self.stringindex = 0

# class Constnum
class Constnum:
    def __init__(self):
        self.tag = 0
        self.lowbytes = 0

# class Constint
class Constint(Constnum):
    def __init__(self):
        Constnum.__init__(self)

# class Constfloat
class Constfloat(Constnum):
    def __init__(self):
        Constnum.__init__(self)

# class Constbignum
class Constbignum(Constnum):
    def __init__(self):
        Constnum.__init__(self)
        self.highbytes = 0

# class Constlong
class Constlong(Constbignum):
    def __init__(self):
        Constbignum.__init__(self)

# class Constdbl
class Constdbl(Constbignum):
    def __init__(self):
        Constbignum.__init__(self)

# class Constnametype
class Constnametype:
    def __init__(self):
        self.tag = 0
        self.nameindex = 0
        self.descriptorindex = 0

# class Constutf8
class Constutf8:
    def __init__(self):
        self.tag = 0
        self.length = 0
        self.bytes = []

# class Exception
class Exception:
    def __init__(self):
        self.startpc = 0
        self.endpc = 0
        self.handlerpc = 0
        self.catchtype = 0

# class Attribute
class Attribute:
    def __init__(self):
        self.nameindex = 0
        self.length = 0
        self.info = []

# class Constattr
class Constattr:
    def __init__(self):
        self.nameindex = 0
        self.length = 0
        self.constvalindex = 0

# class Codeattr
class Codeattr:
    def __init__(self):
        self.nameindex = 0
        self.length = 0
        self.maxstack = 0
        self.maxlocals = 0
        self.codelength = 0
        self.code = []
        self.etablesize = 0
        self.etable = []
        self.attrcount = 0
        self.attributes = []

# class Element
class Element:
    def __init__(self):
        self.accessflags = 0
        self.nameindex = 0
        self.descriptorindex = 0
        self.attrcount = 0
        self.attributes = []

# class Field
class Field(Element):
    def __init__(self):
        Element.__init__(self)

# class Method
class Method(Element):
    def __init__(self):
        Element.__init__(self)

# function errorandexit
def errorandexit(msg):
    print msg
    sys.exit(0)

# Main function
if __name__ == '__main__':
    import sys, os, string
    
    # Local variables
    filename = None
    classfile = None
    
    if len(sys.argv) < 2:
        errorandexit('Usage: ./disasm.py <classfilename>\n')
        
    filename = str(sys.argv[1])
        
    try:
        file = open(filename, 'r')
    except IOError:
        errorstr = 'File ' + filename + ' does not exist\n'
        errorandexit(errorstr)
        
    cr = Classreader(filename)
    classfile = cr.__readclass__()
    clsdump = Classdump()
    clsdump.dumpclass(classfile)
