/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.apf;

import static android.net.apf.ApfGenerator.Register.R0;
import static android.net.apf.ApfGenerator.Register.R1;

import androidx.annotation.NonNull;

import com.android.internal.annotations.VisibleForTesting;
import com.android.net.module.util.HexDump;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * APF assembler/generator.  A tool for generating an APF program.
 *
 * Call add*() functions to add instructions to the program, then call
 * {@link ApfGenerator#generate} to get the APF bytecode for the program.
 *
 * @hide
 */
public class ApfGenerator {
    /**
     * This exception is thrown when an attempt is made to generate an illegal instruction.
     */
    public static class IllegalInstructionException extends Exception {
        IllegalInstructionException(String msg) {
            super(msg);
        }
    }
    private enum Opcodes {
        LABEL(-1),
        // Unconditionally pass (if R=0) or drop (if R=1) packet.
        // An optional unsigned immediate value can be provided to encode the counter number.
        // If the value is non-zero, the instruction increments the counter.
        // The counter is located (-4 * counter number) bytes from the end of the data region.
        // It is a U32 big-endian value and is always incremented by 1.
        // This is more or less equivalent to: lddw R0, -N4; add R0,1; stdw R0, -N4; {pass,drop}
        // e.g. "pass", "pass 1", "drop", "drop 1"
        PASS(0),
        DROP(0),
        LDB(1),    // Load 1 byte from immediate offset, e.g. "ldb R0, [5]"
        LDH(2),    // Load 2 bytes from immediate offset, e.g. "ldh R0, [5]"
        LDW(3),    // Load 4 bytes from immediate offset, e.g. "ldw R0, [5]"
        LDBX(4),   // Load 1 byte from immediate offset plus register, e.g. "ldbx R0, [5]R0"
        LDHX(5),   // Load 2 byte from immediate offset plus register, e.g. "ldhx R0, [5]R0"
        LDWX(6),   // Load 4 byte from immediate offset plus register, e.g. "ldwx R0, [5]R0"
        ADD(7),    // Add, e.g. "add R0,5"
        MUL(8),    // Multiply, e.g. "mul R0,5"
        DIV(9),    // Divide, e.g. "div R0,5"
        AND(10),   // And, e.g. "and R0,5"
        OR(11),    // Or, e.g. "or R0,5"
        SH(12),    // Left shift, e.g, "sh R0, 5" or "sh R0, -5" (shifts right)
        LI(13),    // Load immediate, e.g. "li R0,5" (immediate encoded as signed value)
        // Jump, e.g. "jmp label"
        // In APFv6, we use JMP(R=1) to encode the DATA instruction. DATA is executed as a jump.
        // It tells how many bytes of the program regions are used to store the data and followed
        // by the actual data bytes.
        // "e.g. data 5, abcde"
        JMP(14),
        JEQ(15),   // Compare equal and branch, e.g. "jeq R0,5,label"
        JNE(16),   // Compare not equal and branch, e.g. "jne R0,5,label"
        JGT(17),   // Compare greater than and branch, e.g. "jgt R0,5,label"
        JLT(18),   // Compare less than and branch, e.g. "jlt R0,5,label"
        JSET(19),  // Compare any bits set and branch, e.g. "jset R0,5,label"
        JNEBS(20), // Compare not equal byte sequence, e.g. "jnebs R0,5,label,0x1122334455"
        EXT(21),   // Followed by immediate indicating ExtendedOpcodes.
        LDDW(22),  // Load 4 bytes from data memory address (register + immediate): "lddw R0, [5]R1"
        STDW(23),  // Store 4 bytes to data memory address (register + immediate): "stdw R0, [5]R1"
        // Write 1, 2 or 4 bytes immediate to the output buffer and auto-increment the pointer to
        // write. e.g. "write 5"
        WRITE(24),
        // Copy bytes from input packet/APF program/data region to output buffer and
        // auto-increment the output buffer pointer.
        // Register bit is used to specify the source of data copy.
        // R=0 means copy from packet.
        // R=1 means copy from APF program/data region.
        // The copy length is stored in (u8)imm2.
        // e.g. "pktcopy 5, 5" "datacopy 5, 5"
        PKTDATACOPY(25);

        final int value;

        private Opcodes(int value) {
            this.value = value;
        }
    }
    // Extended opcodes. Primary opcode is Opcodes.EXT. ExtendedOpcodes are encoded in the immediate
    // field.
    private enum ExtendedOpcodes {
        LDM(0),   // Load from memory, e.g. "ldm R0,5"
        STM(16),  // Store to memory, e.g. "stm R0,5"
        NOT(32),  // Not, e.g. "not R0"
        NEG(33),  // Negate, e.g. "neg R0"
        SWAP(34), // Swap, e.g. "swap R0,R1"
        MOVE(35),  // Move, e.g. "move R0,R1"
        // Allocate writable output buffer.
        // R=0, use register R0 to store the length. R=1, encode the length in the u16 int imm2.
        // "e.g. allocate R0"
        // "e.g. allocate 123"
        ALLOCATE(36),
        //  Transmit and deallocate the buffer (transmission can be delayed until the program
        //  terminates). R=0 means discard the buffer, R=1 means transmit the buffer.
        // "e.g. trans"
        // "e.g. discard"
        TRANSMIT(37),
        DISCARD(37),
        // Write 1, 2 or 4 byte value from register to the output buffer and auto-increment the
        // output buffer pointer.
        // e.g. "ewrite1 r0"
        EWRITE1(38),
        EWRITE2(39),
        EWRITE4(40),
        // Copy bytes from input packet/APF program/data region to output buffer and
        // auto-increment the output buffer pointer.
        // The copy src offset is stored in R0.
        // when R=0, the copy length is stored in (u8)imm2.
        // when R=1, the copy length is stored in R1.
        // e.g. "pktcopy r0, 5", "pktcopy r0, r1", "datacopy r0, 5", "datacopy r0, r1"
        EPKTCOPY(41),
        EDATACOPY(42),
        // Jumps if the UDP payload content (starting at R0) does not contain ont
        // of the specified QNAME, applying case insensitivity.
        // R0: Offset to UDP payload content
        // R=0/1 meanining 'does not match' vs 'matches'
        // imm1: Opcode
        // imm2: Label offset
        // imm3(u8): Question type (PTR/SRV/TXT/A/AAAA)
        // imm4(bytes): TLV-encoded QNAME list (null-terminated)
        // e.g.: "jdnsqmatch R0,label,0x0c,\002aa\005local\0\0"
        JDNSQMATCH(43), // Jumps if the UDP payload content (starting at R0) does not contain one
        // of the specified NAME in answers/authority/additional records, applying
        // case insensitivity.
        // R=0/1 meanining 'does not match' vs 'matches'
        // R0: Offset to UDP payload content
        // imm1: Opcode
        // imm2: Label offset
        // imm3(bytes): TLV-encoded QNAME list (null-terminated)
        // e.g.: "jdnsamatch R0,label,0x0c,\002aa\005local\0\0"
        JDNSAMATCH(44);

        final int value;

        private ExtendedOpcodes(int value) {
            this.value = value;
        }
    }
    public enum Register {
        R0(0),
        R1(1);

        final int value;

        private Register(int value) {
            this.value = value;
        }
    }

    private enum IntImmediateType {
        INDETERMINATE_SIZE_SIGNED,
        INDETERMINATE_SIZE_UNSIGNED,
        SIGNED_8,
        UNSIGNED_8,
        SIGNED_BE16,
        UNSIGNED_BE16,
        SIGNED_BE32,
        UNSIGNED_BE32;
    }

    private static class IntImmediate {
        public final IntImmediateType mImmediateType;
        public final int mValue;

        IntImmediate(int value, IntImmediateType type) {
            mImmediateType = type;
            mValue = value;
        }

        private int calculateIndeterminateSize() {
            switch (mImmediateType) {
                case INDETERMINATE_SIZE_SIGNED:
                    return calculateImmSize(mValue, true /* signed */);
                case INDETERMINATE_SIZE_UNSIGNED:
                    return calculateImmSize(mValue, false /* signed */);
                default:
                    // For IMM with determinate size, return 0 to allow Math.max() calculation in
                    // caller function.
                    return 0;
            }
        }

        private int getEncodingSize(int immFieldSize) {
            switch (mImmediateType) {
                case SIGNED_8:
                case UNSIGNED_8:
                    return 1;
                case SIGNED_BE16:
                case UNSIGNED_BE16:
                    return 2;
                case SIGNED_BE32:
                case UNSIGNED_BE32:
                    return 4;
                case INDETERMINATE_SIZE_SIGNED:
                case INDETERMINATE_SIZE_UNSIGNED: {
                    int minSizeRequired = calculateIndeterminateSize();
                    if (minSizeRequired > immFieldSize) {
                        throw new IllegalStateException(
                                String.format("immFieldSize: %d is too small to encode value %d",
                                        immFieldSize, mValue));
                    }
                    return immFieldSize;
                }
            }
            throw new IllegalStateException("UnhandledInvalid IntImmediateType: " + mImmediateType);
        }

        private int writeValue(byte[] bytecode, Integer writingOffset, int immFieldSize) {
            return Instruction.writeValue(mValue, bytecode, writingOffset,
                    getEncodingSize(immFieldSize));
        }

        public static IntImmediate newSigned(int imm) {
            return new IntImmediate(imm, IntImmediateType.INDETERMINATE_SIZE_SIGNED);
        }

        public static IntImmediate newUnsigned(long imm) {
            // upperBound is 2^32 - 1
            checkRange("Unsigned IMM", imm, 0 /* lowerBound */,
                    4294967295L /* upperBound */);
            return new IntImmediate((int) imm, IntImmediateType.INDETERMINATE_SIZE_UNSIGNED);
        }

        public static IntImmediate newTwosComplementUnsigned(long imm) {
            checkRange("Unsigned TwosComplement IMM", imm, Integer.MIN_VALUE,
                    4294967295L /* upperBound */);
            return new IntImmediate((int) imm, IntImmediateType.INDETERMINATE_SIZE_UNSIGNED);
        }

        public static IntImmediate newTwosComplementSigned(long imm) {
            checkRange("Signed TwosComplement IMM", imm, Integer.MIN_VALUE,
                    4294967295L /* upperBound */);
            return new IntImmediate((int) imm, IntImmediateType.INDETERMINATE_SIZE_SIGNED);
        }

        public static IntImmediate newS8(byte imm) {
            checkRange("S8 IMM", imm, Byte.MIN_VALUE, Byte.MAX_VALUE);
            return new IntImmediate(imm, IntImmediateType.SIGNED_8);
        }

        public static IntImmediate newU8(int imm) {
            checkRange("U8 IMM", imm, 0, 255);
            return new IntImmediate(imm, IntImmediateType.UNSIGNED_8);
        }

        public static IntImmediate newS16(short imm) {
            return new IntImmediate(imm, IntImmediateType.SIGNED_BE16);
        }

        public static IntImmediate newU16(int imm) {
            checkRange("U16 IMM", imm, 0, 65535);
            return new IntImmediate(imm, IntImmediateType.UNSIGNED_BE16);
        }

        public static IntImmediate newS32(int imm) {
            return new IntImmediate(imm, IntImmediateType.SIGNED_BE32);
        }

        public static IntImmediate newU32(long imm) {
            // upperBound is 2^32 - 1
            checkRange("U32 IMM", imm, 0 /* lowerBound */,
                    4294967295L /* upperBound */);
            return new IntImmediate((int) imm, IntImmediateType.UNSIGNED_BE32);
        }

        @Override
        public String toString() {
            return "IntImmediate{" + "mImmediateType=" + mImmediateType + ", mValue=" + mValue
                    + '}';
        }
    }

    private class Instruction {
        private final byte mOpcode;   // A "Opcode" value.
        private final byte mRegister; // A "Register" value.
        public final List<IntImmediate> mIntImms = new ArrayList<>();
        // When mOpcode is a jump:
        private int mTargetLabelSize;
        private int mLenFieldOverride = -1;
        private String mTargetLabel;
        // When mOpcode == Opcodes.LABEL:
        private String mLabel;
        private byte[] mBytesImm;
        // Offset in bytes from the beginning of this program. Set by {@link ApfGenerator#generate}.
        int offset;

        Instruction(Opcodes opcode, Register register) {
            mOpcode = (byte) opcode.value;
            mRegister = (byte) register.value;
        }

        Instruction(ExtendedOpcodes extendedOpcodes, Register register) {
            this(Opcodes.EXT, register);
            addUnsigned(extendedOpcodes.value);
        }

        Instruction(ExtendedOpcodes extendedOpcodes, int slot, Register register)
                throws IllegalInstructionException {
            this(Opcodes.EXT, register);
            if (slot < 0 || slot >= MEMORY_SLOTS) {
                throw new IllegalInstructionException("illegal memory slot number: " + slot);
            }
            addUnsigned(extendedOpcodes.value + slot);
        }

        Instruction(Opcodes opcode) {
            this(opcode, R0);
        }

        Instruction(ExtendedOpcodes extendedOpcodes) {
            this(extendedOpcodes, R0);
        }

        Instruction addSigned(int imm) {
            mIntImms.add(IntImmediate.newSigned(imm));
            return this;
        }

        Instruction addUnsigned(int imm) {
            mIntImms.add(IntImmediate.newUnsigned(imm));
            return this;
        }


        Instruction addTwosCompSigned(int imm) {
            mIntImms.add(IntImmediate.newTwosComplementSigned(imm));
            return this;
        }


        Instruction addTwosCompUnsigned(int imm) {
            mIntImms.add(IntImmediate.newTwosComplementUnsigned(imm));
            return this;
        }

        Instruction addS8(byte imm) {
            mIntImms.add(IntImmediate.newS8(imm));
            return this;
        }

        Instruction addU8(int imm) {
            mIntImms.add(IntImmediate.newU8(imm));
            return this;
        }

        Instruction addS16(short imm) {
            mIntImms.add(IntImmediate.newS16(imm));
            return this;
        }

        Instruction addU16(int imm) {
            mIntImms.add(IntImmediate.newU16(imm));
            return this;
        }

        Instruction addS32(int imm) {
            mIntImms.add(IntImmediate.newS32(imm));
            return this;
        }

        Instruction addU32(long imm) {
            mIntImms.add(IntImmediate.newU32(imm));
            return this;
        }

        Instruction setLabel(String label) throws IllegalInstructionException {
            if (mLabels.containsKey(label)) {
                throw new IllegalInstructionException("duplicate label " + label);
            }
            if (mOpcode != Opcodes.LABEL.value) {
                throw new IllegalStateException("adding label to non-label instruction");
            }
            mLabel = label;
            mLabels.put(label, this);
            return this;
        }

        Instruction setTargetLabel(String label) {
            mTargetLabel = label;
            mTargetLabelSize = 4; // May shrink later on in generate().
            return this;
        }

        Instruction overrideLenField(int size) {
            mLenFieldOverride = size;
            return this;
        }

        Instruction setBytesImm(byte[] bytes) {
            mBytesImm = bytes;
            return this;
        }

        /**
         * @return size of instruction in bytes.
         */
        int size() {
            if (mOpcode == Opcodes.LABEL.value) {
                return 0;
            }
            int size = 1;
            int indeterminateSize = calculateRequiredIndeterminateSize();
            for (IntImmediate imm : mIntImms) {
                size += imm.getEncodingSize(indeterminateSize);
            }
            if (mTargetLabel != null) {
                size += indeterminateSize;
            }
            if (mBytesImm != null) {
                size += mBytesImm.length;
            }
            return size;
        }

        /**
         * Resize immediate value field so that it's only as big as required to
         * contain the offset of the jump destination.
         * @return {@code true} if shrunk.
         */
        boolean shrink() throws IllegalInstructionException {
            if (mTargetLabel == null) {
                return false;
            }
            int oldTargetLabelSize = mTargetLabelSize;
            mTargetLabelSize = calculateImmSize(calculateTargetLabelOffset(), false);
            if (mTargetLabelSize > oldTargetLabelSize) {
                throw new IllegalStateException("instruction grew");
            }
            return mTargetLabelSize < oldTargetLabelSize;
        }

        /**
         * Assemble value for instruction size field.
         */
        private int generateImmSizeField() {
            // If we already know the size the length field, just use it
            switch (mLenFieldOverride) {
                case -1:
                    break;
                case 1:
                    return 1;
                case 2:
                    return 2;
                case 4:
                    return 3;
                default:
                    throw new IllegalStateException(
                            "mLenFieldOverride has invalid value: " + mLenFieldOverride);
            }
            // Otherwise, calculate
            int immSize = calculateRequiredIndeterminateSize();
            // Encode size field to fit in 2 bits: 0->0, 1->1, 2->2, 3->4.
            return immSize == 4 ? 3 : immSize;
        }

        /**
         * Assemble first byte of generated instruction.
         */
        private byte generateInstructionByte() {
            int sizeField = generateImmSizeField();
            return (byte)((mOpcode << 3) | (sizeField << 1) | mRegister);
        }

        /**
         * Write {@code value} at offset {@code writingOffset} into {@code bytecode}.
         * {@code immSize} bytes are written. {@code value} is truncated to
         * {@code immSize} bytes. {@code value} is treated simply as a
         * 32-bit value, so unsigned values should be zero extended and the truncation
         * should simply throw away their zero-ed upper bits, and signed values should
         * be sign extended and the truncation should simply throw away their signed
         * upper bits.
         */
        private static int writeValue(int value, byte[] bytecode, int writingOffset, int immSize) {
            for (int i = immSize - 1; i >= 0; i--) {
                bytecode[writingOffset++] = (byte)((value >> (i * 8)) & 255);
            }
            return writingOffset;
        }

        /**
         * Generate bytecode for this instruction at offset {@link Instruction#offset}.
         */
        void generate(byte[] bytecode) throws IllegalInstructionException {
            if (mOpcode == Opcodes.LABEL.value) {
                return;
            }
            int writingOffset = offset;
            bytecode[writingOffset++] = generateInstructionByte();
            int indeterminateSize = calculateRequiredIndeterminateSize();
            int startOffset = 0;
            if (mOpcode == Opcodes.EXT.value) {
                // For extend opcode, always write the actual opcode first.
                writingOffset = mIntImms.get(startOffset++).writeValue(bytecode, writingOffset,
                        indeterminateSize);
            }
            if (mTargetLabel != null) {
                writingOffset = writeValue(calculateTargetLabelOffset(), bytecode, writingOffset,
                        indeterminateSize);
            }
            for (int i = startOffset; i < mIntImms.size(); ++i) {
                writingOffset = mIntImms.get(i).writeValue(bytecode, writingOffset,
                        indeterminateSize);
            }
            if (mBytesImm != null) {
                System.arraycopy(mBytesImm, 0, bytecode, writingOffset, mBytesImm.length);
                writingOffset += mBytesImm.length;
            }
            if ((writingOffset - offset) != size()) {
                throw new IllegalStateException("wrote " + (writingOffset - offset) +
                        " but should have written " + size());
            }
        }

        /**
         * Calculates the maximum indeterminate size of all IMMs in this instruction.
         * <p>
         * This method finds the largest size needed to encode any indeterminate-sized IMMs in
         * the instruction. This size will be stored in the immLen field.
         */
        private int calculateRequiredIndeterminateSize() {
            int maxSize = mTargetLabelSize;
            for (IntImmediate imm : mIntImms) {
                maxSize = Math.max(maxSize, imm.calculateIndeterminateSize());
            }
            return maxSize;
        }

        private int calculateTargetLabelOffset() throws IllegalInstructionException {
            Instruction targetLabelInstruction;
            if (mTargetLabel == DROP_LABEL) {
                targetLabelInstruction = mDropLabel;
            } else if (mTargetLabel == PASS_LABEL) {
                targetLabelInstruction = mPassLabel;
            } else {
                targetLabelInstruction = mLabels.get(mTargetLabel);
            }
            if (targetLabelInstruction == null) {
                throw new IllegalInstructionException("label not found: " + mTargetLabel);
            }
            // Calculate distance from end of this instruction to instruction.offset.
            final int targetLabelOffset = targetLabelInstruction.offset - (offset + size());
            return targetLabelOffset;
        }
    }

    /**
     * Jump to this label to terminate the program and indicate the packet
     * should be dropped.
     */
    public static final String DROP_LABEL = "__DROP__";

    /**
     * Jump to this label to terminate the program and indicate the packet
     * should be passed to the AP.
     */
    public static final String PASS_LABEL = "__PASS__";

    /**
     * Number of memory slots available for access via APF stores to memory and loads from memory.
     * The memory slots are numbered 0 to {@code MEMORY_SLOTS} - 1. This must be kept in sync with
     * the APF interpreter.
     */
    public static final int MEMORY_SLOTS = 16;

    /**
     * Memory slot number that is prefilled with the IPv4 header length.
     * Note that this memory slot may be overwritten by a program that
     * executes stores to this memory slot. This must be kept in sync with
     * the APF interpreter.
     */
    public static final int IPV4_HEADER_SIZE_MEMORY_SLOT = 13;

    /**
     * Memory slot number that is prefilled with the size of the packet being filtered in bytes.
     * Note that this memory slot may be overwritten by a program that
     * executes stores to this memory slot. This must be kept in sync with the APF interpreter.
     */
    public static final int PACKET_SIZE_MEMORY_SLOT = 14;

    /**
     * Memory slot number that is prefilled with the age of the filter in seconds. The age of the
     * filter is the time since the filter was installed until now.
     * Note that this memory slot may be overwritten by a program that
     * executes stores to this memory slot. This must be kept in sync with the APF interpreter.
     */
    public static final int FILTER_AGE_MEMORY_SLOT = 15;

    /**
     * First memory slot containing prefilled values. Can be used in range comparisons to determine
     * if memory slot index is within prefilled slots.
     */
    public static final int FIRST_PREFILLED_MEMORY_SLOT = IPV4_HEADER_SIZE_MEMORY_SLOT;

    /**
     * Last memory slot containing prefilled values. Can be used in range comparisons to determine
     * if memory slot index is within prefilled slots.
     */
    public static final int LAST_PREFILLED_MEMORY_SLOT = FILTER_AGE_MEMORY_SLOT;

    // This version number syncs up with APF_VERSION in hardware/google/apf/apf_interpreter.h
    public static final int MIN_APF_VERSION = 2;
    public static final int MIN_APF_VERSION_IN_DEV = 5;
    public static final int APF_VERSION_4 = 4;


    private final ArrayList<Instruction> mInstructions = new ArrayList<Instruction>();
    private final HashMap<String, Instruction> mLabels = new HashMap<String, Instruction>();
    private final Instruction mDropLabel = new Instruction(Opcodes.LABEL);
    private final Instruction mPassLabel = new Instruction(Opcodes.LABEL);
    private final int mVersion;
    private boolean mGenerated;

    /**
     * Creates an ApfGenerator instance which is able to emit instructions for the specified
     * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
     * the requested version is unsupported.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public ApfGenerator(int version) throws IllegalInstructionException {
        mVersion = version;
        requireApfVersion(MIN_APF_VERSION);
    }

    /**
     * Returns true if the ApfGenerator supports the specified {@code version}, otherwise false.
     */
    public static boolean supportsVersion(int version) {
        return version >= MIN_APF_VERSION;
    }

    private void requireApfVersion(int minimumVersion) throws IllegalInstructionException {
        if (mVersion < minimumVersion) {
            throw new IllegalInstructionException("Requires APF >= " + minimumVersion);
        }
    }

    private ApfGenerator append(Instruction instruction) {
        if (mGenerated) {
            throw new IllegalStateException("Program already generated");
        }
        mInstructions.add(instruction);
        return this;
    }

    /**
     * Define a label at the current end of the program. Jumps can jump to this label. Labels are
     * their own separate instructions, though with size 0. This facilitates having labels with
     * no corresponding code to execute, for example a label at the end of a program. For example
     * an {@link ApfGenerator} might be passed to a function that adds a filter like so:
     * <pre>
     *   load from packet
     *   compare loaded data, jump if not equal to "next_filter"
     *   load from packet
     *   compare loaded data, jump if not equal to "next_filter"
     *   jump to drop label
     *   define "next_filter" here
     * </pre>
     * In this case "next_filter" may not have any generated code associated with it.
     */
    public ApfGenerator defineLabel(String name) throws IllegalInstructionException {
        return append(new Instruction(Opcodes.LABEL).setLabel(name));
    }

    /**
     * Add an unconditional jump instruction to the end of the program.
     */
    public ApfGenerator addJump(String target) {
        return append(new Instruction(Opcodes.JMP).setTargetLabel(target));
    }

    /**
     * Add an instruction to the end of the program to load the byte at offset {@code offset}
     * bytes from the beginning of the packet into {@code register}.
     */
    public ApfGenerator addLoad8(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDB, r).addUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 16-bits at offset {@code offset}
     * bytes from the beginning of the packet into {@code register}.
     */
    public ApfGenerator addLoad16(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDH, r).addUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 32-bits at offset {@code offset}
     * bytes from the beginning of the packet into {@code register}.
     */
    public ApfGenerator addLoad32(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDW, r).addUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to load a byte from the packet into
     * {@code register}. The offset of the loaded byte from the beginning of the packet is
     * the sum of {@code offset} and the value in register R1.
     */
    public ApfGenerator addLoad8Indexed(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDBX, r).addUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 16-bits from the packet into
     * {@code register}. The offset of the loaded 16-bits from the beginning of the packet is
     * the sum of {@code offset} and the value in register R1.
     */
    public ApfGenerator addLoad16Indexed(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDHX, r).addUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 32-bits from the packet into
     * {@code register}. The offset of the loaded 32-bits from the beginning of the packet is
     * the sum of {@code offset} and the value in register R1.
     */
    public ApfGenerator addLoad32Indexed(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDWX, r).addUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to add {@code value} to register R0.
     */
    public ApfGenerator addAdd(int val) {
        return append(new Instruction(Opcodes.ADD).addTwosCompUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to multiply register R0 by {@code value}.
     */
    public ApfGenerator addMul(int val) {
        return append(new Instruction(Opcodes.MUL).addUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to divide register R0 by {@code value}.
     */
    public ApfGenerator addDiv(int val) {
        return append(new Instruction(Opcodes.DIV).addUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to logically and register R0 with {@code value}.
     */
    public ApfGenerator addAnd(int val) {
        return append(new Instruction(Opcodes.AND).addTwosCompUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to logically or register R0 with {@code value}.
     */
    public ApfGenerator addOr(int val) {
        return append(new Instruction(Opcodes.OR).addTwosCompUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to shift left register R0 by {@code value} bits.
     */
    // TODO: consider whether should change the argument type to byte
    public ApfGenerator addLeftShift(int val) {
        return append(new Instruction(Opcodes.SH).addSigned(val));
    }

    /**
     * Add an instruction to the end of the program to shift right register R0 by {@code value}
     * bits.
     */
    // TODO: consider whether should change the argument type to byte
    public ApfGenerator addRightShift(int val) {
        return append(new Instruction(Opcodes.SH).addSigned(-val));
    }

    /**
     * Add an instruction to the end of the program to add register R1 to register R0.
     */
    public ApfGenerator addAddR1() {
        return append(new Instruction(Opcodes.ADD, R1));
    }

    /**
     * Add an instruction to the end of the program to multiply register R0 by register R1.
     */
    public ApfGenerator addMulR1() {
        return append(new Instruction(Opcodes.MUL, R1));
    }

    /**
     * Add an instruction to the end of the program to divide register R0 by register R1.
     */
    public ApfGenerator addDivR1() {
        return append(new Instruction(Opcodes.DIV, R1));
    }

    /**
     * Add an instruction to the end of the program to logically and register R0 with register R1
     * and store the result back into register R0.
     */
    public ApfGenerator addAndR1() {
        return append(new Instruction(Opcodes.AND, R1));
    }

    /**
     * Add an instruction to the end of the program to logically or register R0 with register R1
     * and store the result back into register R0.
     */
    public ApfGenerator addOrR1() {
        return append(new Instruction(Opcodes.OR, R1));
    }

    /**
     * Add an instruction to the end of the program to shift register R0 left by the value in
     * register R1.
     */
    public ApfGenerator addLeftShiftR1() {
        return append(new Instruction(Opcodes.SH, R1));
    }

    /**
     * Add an instruction to the end of the program to move {@code value} into {@code register}.
     */
    public ApfGenerator addLoadImmediate(Register register, int value) {
        return append(new Instruction(Opcodes.LI, register).addSigned(value));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value equals {@code value}.
     */
    public ApfGenerator addJumpIfR0Equals(int val, String tgt) {
        return append(new Instruction(Opcodes.JEQ).addTwosCompUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value does not equal {@code value}.
     */
    public ApfGenerator addJumpIfR0NotEquals(int val, String tgt) {
        return append(new Instruction(Opcodes.JNE).addTwosCompUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is greater than {@code value}.
     */
    public ApfGenerator addJumpIfR0GreaterThan(int val, String tgt) {
        return append(new Instruction(Opcodes.JGT).addUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is less than {@code value}.
     */
    public ApfGenerator addJumpIfR0LessThan(int val, String tgt) {
        return append(new Instruction(Opcodes.JLT).addUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value has any bits set that are also set in {@code value}.
     */
    public ApfGenerator addJumpIfR0AnyBitsSet(int val, String tgt) {
        return append(new Instruction(Opcodes.JSET).addTwosCompUnsigned(val).setTargetLabel(tgt));
    }
    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value equals register R1's value.
     */
    public ApfGenerator addJumpIfR0EqualsR1(String tgt) {
        return append(new Instruction(Opcodes.JEQ, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value does not equal register R1's value.
     */
    public ApfGenerator addJumpIfR0NotEqualsR1(String tgt) {
        return append(new Instruction(Opcodes.JNE, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is greater than register R1's value.
     */
    public ApfGenerator addJumpIfR0GreaterThanR1(String tgt) {
        return append(new Instruction(Opcodes.JGT, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is less than register R1's value.
     */
    public ApfGenerator addJumpIfR0LessThanR1(String target) {
        return append(new Instruction(Opcodes.JLT, R1).setTargetLabel(target));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value has any bits set that are also set in R1's value.
     */
    public ApfGenerator addJumpIfR0AnyBitsSetR1(String tgt) {
        return append(new Instruction(Opcodes.JSET, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code tgt} if the bytes of the
     * packet at an offset specified by {@code register} don't match {@code bytes}
     * R=0 means check for not equal
     */
    public ApfGenerator addJumpIfBytesAtR0NotEqual(byte[] bytes, String tgt) {
        return append(new Instruction(Opcodes.JNEBS).addUnsigned(
                bytes.length).setTargetLabel(tgt).setBytesImm(bytes));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code tgt} if the bytes of the
     * packet at an offset specified by {@code register} match {@code bytes}
     * R=1 means check for equal.
     */
    public ApfGenerator addJumpIfBytesAtR0Equal(byte[] bytes, String tgt)
            throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(Opcodes.JNEBS, R1).addUnsigned(
                bytes.length).setTargetLabel(tgt).setBytesImm(bytes));
    }

    /**
     * Add an instruction to the end of the program to load memory slot {@code slot} into
     * {@code register}.
     */
    public ApfGenerator addLoadFromMemory(Register r, int slot)
            throws IllegalInstructionException {
        return append(new Instruction(ExtendedOpcodes.LDM, slot, r));
    }

    /**
     * Add an instruction to the end of the program to store {@code register} into memory slot
     * {@code slot}.
     */
    public ApfGenerator addStoreToMemory(Register r, int slot)
            throws IllegalInstructionException {
        return append(new Instruction(ExtendedOpcodes.STM, slot, r));
    }

    /**
     * Add an instruction to the end of the program to logically not {@code register}.
     */
    public ApfGenerator addNot(Register r) {
        return append(new Instruction(ExtendedOpcodes.NOT, r));
    }

    /**
     * Add an instruction to the end of the program to negate {@code register}.
     */
    public ApfGenerator addNeg(Register r) {
        return append(new Instruction(ExtendedOpcodes.NEG, r));
    }

    /**
     * Add an instruction to swap the values in register R0 and register R1.
     */
    public ApfGenerator addSwap() {
        return append(new Instruction(ExtendedOpcodes.SWAP));
    }

    /**
     * Add an instruction to the end of the program to move the value into
     * {@code register} from the other register.
     */
    public ApfGenerator addMove(Register r) {
        return append(new Instruction(ExtendedOpcodes.MOVE, r));
    }

    /**
     * Add an instruction to the end of the program to let the program immediately return PASS.
     */
    public ApfGenerator addPass() {
        // PASS requires using R0 because it shares opcode with DROP
        return append(new Instruction(Opcodes.PASS));
    }

    /**
     * Add an instruction to the end of the program to increment the counter value and
     * immediately return PASS.
     */
    public ApfGenerator addCountAndPass(int cnt) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        checkRange("CounterNumber", cnt /* value */, 1 /* lowerBound */,
                1000 /* upperBound */);
        // PASS requires using R0 because it shares opcode with DROP
        return append(new Instruction(Opcodes.PASS).addUnsigned(cnt));
    }

    /**
     * Add an instruction to the end of the program to let the program immediately return DROP.
     */
    public ApfGenerator addDrop() throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        // DROP requires using R1 because it shares opcode with PASS
        return append(new Instruction(Opcodes.DROP, R1));
    }

    /**
     * Add an instruction to the end of the program to increment the counter value and
     * immediately return DROP.
     */
    public ApfGenerator addCountAndDrop(int cnt) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        checkRange("CounterNumber", cnt /* value */, 1 /* lowerBound */,
                1000 /* upperBound */);
        // DROP requires using R1 because it shares opcode with PASS
        return append(new Instruction(Opcodes.DROP, R1).addUnsigned(cnt));
    }

    /**
     * Add an instruction to the end of the program to call the apf_allocate_buffer() function.
     * Buffer length to be allocated is stored in register 0.
     */
    public ApfGenerator addAllocateR0() throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.ALLOCATE));
    }

    /**
     * Add an instruction to the end of the program to call the apf_allocate_buffer() function.
     *
     * @param size the buffer length to be allocated.
     */
    public ApfGenerator addAllocate(int size) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        // R1 means the extra be16 immediate is present
        return append(new Instruction(ExtendedOpcodes.ALLOCATE, R1).addU16(size));
    }

    /**
     * Add an instruction to the beginning of the program to reserve the data region.
     * @param data the actual data byte
     */
    public ApfGenerator addData(byte[] data) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        if (!mInstructions.isEmpty()) {
            throw new IllegalInstructionException("data instruction has to come first");
        }
        return append(new Instruction(Opcodes.JMP, R1).addUnsigned(data.length).setBytesImm(data));
    }

    /**
     * Add an instruction to the end of the program to transmit the allocated buffer.
     */
    public ApfGenerator addTransmit() throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        // TRANSMIT requires using R0 because it shares opcode with DISCARD
        return append(new Instruction(ExtendedOpcodes.TRANSMIT));
    }

    /**
     * Add an instruction to the end of the program to discard the allocated buffer.
     */
    public ApfGenerator addDiscard() throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        // DISCARD requires using R1 because it shares opcode with TRANSMIT
        return append(new Instruction(ExtendedOpcodes.DISCARD, R1));
    }

    /**
     * Add an instruction to the end of the program to write 1 byte value to output buffer.
     */
    public ApfGenerator addWriteU8(int val) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(Opcodes.WRITE).overrideLenField(1).addU8(val));
    }

    /**
     * Add an instruction to the end of the program to write 2 bytes value to output buffer.
     */
    public ApfGenerator addWriteU16(int val) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(Opcodes.WRITE).overrideLenField(2).addU16(val));
    }

    /**
     * Add an instruction to the end of the program to write 4 bytes value to output buffer.
     */
    public ApfGenerator addWriteU32(long val) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(Opcodes.WRITE).overrideLenField(4).addU32(val));
    }

    /**
     * Add an instruction to the end of the program to write 1 byte value from register to output
     * buffer.
     */
    public ApfGenerator addWriteU8(Register reg) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.EWRITE1, reg));
    }

    /**
     * Add an instruction to the end of the program to write 2 byte value from register to output
     * buffer.
     */
    public ApfGenerator addWriteU16(Register reg) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.EWRITE2, reg));
    }

    /**
     * Add an instruction to the end of the program to write 4 byte value from register to output
     * buffer.
     */
    public ApfGenerator addWriteU32(Register reg) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.EWRITE4, reg));
    }

    /**
     * Add an instruction to the end of the program to copy data from APF program/data region to
     * output buffer and auto-increment the output buffer pointer.
     *
     * @param src the offset inside the APF program/data region for where to start copy.
     * @param len the length of bytes needed to be copied, only <= 255 bytes can be copied at
     *               one time.
     * @return the ApfGenerator object
     */
    public ApfGenerator addDataCopy(int src, int len)
            throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(Opcodes.PKTDATACOPY, R1).addUnsigned(src).addU8(len));
    }

    /**
     * Add an instruction to the end of the program to copy data from input packet to output
     * buffer and auto-increment the output buffer pointer.
     *
     * @param src the offset inside the input packet for where to start copy.
     * @param len the length of bytes needed to be copied, only <= 255 bytes can be copied at
     *               one time.
     * @return the ApfGenerator object
     */
    public ApfGenerator addPacketCopy(int src, int len)
            throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(Opcodes.PKTDATACOPY, R0).addUnsigned(src).addU8(len));
    }

    /**
     * Add an instruction to the end of the program to copy data from APF program/data region to
     * output buffer and auto-increment the output buffer pointer.
     * Source offset is stored in R0.
     *
     * @param len the number of bytes to be copied, only <= 255 bytes can be copied at once.
     * @return the ApfGenerator object
     */
    public ApfGenerator addDataCopyFromR0(int len) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.EDATACOPY).addU8(len));
    }

    /**
     * Add an instruction to the end of the program to copy data from input packet to output
     * buffer and auto-increment the output buffer pointer.
     * Source offset is stored in R0.
     *
     * @param len the number of bytes to be copied, only <= 255 bytes can be copied at once.
     * @return the ApfGenerator object
     */
    public ApfGenerator addPacketCopyFromR0(int len) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.EPKTCOPY).addU8(len));
    }

    /**
     * Add an instruction to the end of the program to copy data from APF program/data region to
     * output buffer and auto-increment the output buffer pointer.
     * Source offset is stored in R0.
     * Copy length is stored in R1.
     *
     * @return the ApfGenerator object
     */
    public ApfGenerator addDataCopyFromR0LenR1() throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.EDATACOPY, R1));
    }

    /**
     * Add an instruction to the end of the program to copy data from input packet to output
     * buffer and auto-increment the output buffer pointer.
     * Source offset is stored in R0.
     * Copy length is stored in R1.
     *
     * @return the ApfGenerator object
     */
    public ApfGenerator addPacketCopyFromR0LenR1() throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        return append(new Instruction(ExtendedOpcodes.EPKTCOPY, R1));
    }

    /**
     * Check if the byte is valid dns character: A-Z,0-9,-,_
     */
    private static boolean isValidDnsCharacter(byte c) {
        return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    }

    private static void validateNames(@NonNull byte[] names) {
        final int len = names.length;
        if (len < 4) {
            throw new IllegalArgumentException("qnames must have at least length 4");
        }
        final String errorMessage = "qname: " + HexDump.toHexString(names)
                + "is not null-terminated list of TLV-encoded names";
        int i = 0;
        while (i < len - 1) {
            int label_len = names[i++];
            if (label_len < 1 || label_len > 63) {
                throw new IllegalArgumentException(
                        "label len: " + label_len + " must be between 1 and 63");
            }
            if (i + label_len >= len - 1) {
                throw new IllegalArgumentException(errorMessage);
            }
            while (label_len-- > 0) {
                if (!isValidDnsCharacter(names[i++])) {
                    throw new IllegalArgumentException("qname: " + HexDump.toHexString(names)
                            + " contains invalid character");
                }
            }
            if (names[i] == 0) {
                i++; // skip null terminator.
            }
        }
        if (names[len - 1] != 0) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    /**
     * Appends a conditional jump instruction to the program: Jumps to {@code tgt} if the UDP
     * payload's DNS questions do NOT contain the QNAME specified in {@code qnames} and qtype
     * equals {@code qtype}. Examines the payload starting at the offset in R0.
     * R = 0 means check for "does not contain".
     */
    public ApfGenerator addJumpIfPktAtR0DoesNotContainDnsQ(@NonNull byte[] qnames, int qtype,
            @NonNull String tgt) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        validateNames(qnames);
        return append(new Instruction(ExtendedOpcodes.JDNSQMATCH).setTargetLabel(tgt).addU8(
                qtype).setBytesImm(qnames));
    }

    /**
     * Appends a conditional jump instruction to the program: Jumps to {@code tgt} if the UDP
     * payload's DNS questions contain the QNAME specified in {@code qnames} and qtype
     * equals {@code qtype}. Examines the payload starting at the offset in R0.
     * R = 1 means check for "contain".
     */
    public ApfGenerator addJumpIfPktAtR0ContainDnsQ(@NonNull byte[] qnames, int qtype,
            @NonNull String tgt) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        validateNames(qnames);
        return append(new Instruction(ExtendedOpcodes.JDNSQMATCH, R1).setTargetLabel(tgt).addU8(
                qtype).setBytesImm(qnames));
    }

    /**
     * Appends a conditional jump instruction to the program: Jumps to {@code tgt} if the UDP
     * payload's DNS answers/authority/additional records do NOT contain the NAME
     * specified in {@code Names}. Examines the payload starting at the offset in R0.
     * R = 0 means check for "does not contain".
     */
    public ApfGenerator addJumpIfPktAtR0DoesNotContainDnsA(@NonNull byte[] names,
            @NonNull String tgt) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        validateNames(names);
        return append(new Instruction(ExtendedOpcodes.JDNSAMATCH).setTargetLabel(tgt).setBytesImm(
                names));
    }

    /**
     * Appends a conditional jump instruction to the program: Jumps to {@code tgt} if the UDP
     * payload's DNS answers/authority/additional records contain the NAME
     * specified in {@code Names}. Examines the payload starting at the offset in R0.
     * R = 1 means check for "contain".
     */
    public ApfGenerator addJumpIfPktAtR0ContainDnsA(@NonNull byte[] names,
            @NonNull String tgt) throws IllegalInstructionException {
        requireApfVersion(MIN_APF_VERSION_IN_DEV);
        validateNames(names);
        return append(new Instruction(ExtendedOpcodes.JDNSAMATCH, R1).setTargetLabel(
                tgt).setBytesImm(names));
    }

    private static void checkRange(@NonNull String variableName, long value, long lowerBound,
            long upperBound) {
        if (value >= lowerBound && value <= upperBound) {
            return;
        }
        throw new IllegalArgumentException(
                String.format("%s: %d, must be in range [%d, %d]", variableName, value, lowerBound,
                        upperBound));
    }

    /**
     * Add an instruction to the end of the program to load 32 bits from the data memory into
     * {@code register}. The source address is computed by adding the signed immediate
     * @{code offset} to the other register.
     * Requires APF v4 or greater.
     */
    public ApfGenerator addLoadData(Register dst, int ofs)
            throws IllegalInstructionException {
        requireApfVersion(APF_VERSION_4);
        return append(new Instruction(Opcodes.LDDW, dst).addSigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to store 32 bits from {@code register} into the
     * data memory. The destination address is computed by adding the signed immediate
     * @{code offset} to the other register.
     * Requires APF v4 or greater.
     */
    public ApfGenerator addStoreData(Register src, int ofs)
            throws IllegalInstructionException {
        requireApfVersion(APF_VERSION_4);
        return append(new Instruction(Opcodes.STDW, src).addSigned(ofs));
    }

    /**
     * Updates instruction offset fields using latest instruction sizes.
     * @return current program length in bytes.
     */
    private int updateInstructionOffsets() {
        int offset = 0;
        for (Instruction instruction : mInstructions) {
            instruction.offset = offset;
            offset += instruction.size();
        }
        return offset;
    }

    /**
     * Calculate the size of the imm.
     */
    private static int calculateImmSize(int imm, boolean signed) {
        if (imm == 0) {
            return 0;
        }
        if (signed && (imm >= -128 && imm <= 127) || !signed && (imm >= 0 && imm <= 255)) {
            return 1;
        }
        if (signed && (imm >= -32768 && imm <= 32767) || !signed && (imm >= 0 && imm <= 65535)) {
            return 2;
        }
        return 4;
    }

    /**
     * Returns an overestimate of the size of the generated program. {@link #generate} may return
     * a program that is smaller.
     */
    public int programLengthOverEstimate() {
        return updateInstructionOffsets();
    }

    /**
     * Generate the bytecode for the APF program.
     * @return the bytecode.
     * @throws IllegalStateException if a label is referenced but not defined.
     */
    public byte[] generate() throws IllegalInstructionException {
        // Enforce that we can only generate once because we cannot unshrink instructions and
        // PASS/DROP labels may move further away requiring unshrinking if we add further
        // instructions.
        if (mGenerated) {
            throw new IllegalStateException("Can only generate() once!");
        }
        mGenerated = true;
        int total_size;
        boolean shrunk;
        // Shrink the immediate value fields of instructions.
        // As we shrink the instructions some branch offset
        // fields may shrink also, thereby shrinking the
        // instructions further. Loop until we've reached the
        // minimum size. Rarely will this loop more than a few times.
        // Limit iterations to avoid O(n^2) behavior.
        int iterations_remaining = 10;
        do {
            total_size = updateInstructionOffsets();
            // Update drop and pass label offsets.
            mDropLabel.offset = total_size + 1;
            mPassLabel.offset = total_size;
            // Limit run-time in aberant circumstances.
            if (iterations_remaining-- == 0) break;
            // Attempt to shrink instructions.
            shrunk = false;
            for (Instruction instruction : mInstructions) {
                if (instruction.shrink()) {
                    shrunk = true;
                }
            }
        } while (shrunk);
        // Generate bytecode for instructions.
        byte[] bytecode = new byte[total_size];
        for (Instruction instruction : mInstructions) {
            instruction.generate(bytecode);
        }
        return bytecode;
    }
}

