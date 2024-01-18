/*
 * Copyright (C) 2023 The Android Open Source Project
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
package android.net.apf

import android.net.apf.ApfV4Generator.IllegalInstructionException
import android.net.apf.ApfV4Generator.MIN_APF_VERSION
import android.net.apf.ApfV4Generator.MIN_APF_VERSION_IN_DEV
import android.net.apf.ApfV4Generator.Register.R0
import android.net.apf.ApfV4Generator.Register.R1
import androidx.test.filters.SmallTest
import androidx.test.runner.AndroidJUnit4
import java.lang.IllegalArgumentException
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Tests for APFv6 specific instructions.
 */
@RunWith(AndroidJUnit4::class)
@SmallTest
class ApfV5Test {

    @Test
    fun testApfInstructionVersionCheck() {
        var gen = ApfV4Generator(MIN_APF_VERSION)
        assertFailsWith<IllegalInstructionException> { gen.addDrop() }
        assertFailsWith<IllegalInstructionException> { gen.addCountAndDrop(12) }
        assertFailsWith<IllegalInstructionException> { gen.addCountAndPass(1000) }
        assertFailsWith<IllegalInstructionException> { gen.addTransmit() }
        assertFailsWith<IllegalInstructionException> { gen.addDiscard() }
        assertFailsWith<IllegalInstructionException> { gen.addAllocateR0() }
        assertFailsWith<IllegalInstructionException> { gen.addAllocate(100) }
        assertFailsWith<IllegalInstructionException> { gen.addData(ByteArray(3) { 0x01 }) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU8(100) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU16(100) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU32(100) }
        assertFailsWith<IllegalInstructionException> { gen.addPacketCopy(100, 100) }
        assertFailsWith<IllegalInstructionException> { gen.addDataCopy(100, 100) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU8(R0) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU16(R0) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU32(R0) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU8(R1) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU16(R1) }
        assertFailsWith<IllegalInstructionException> { gen.addWriteU32(R1) }
        assertFailsWith<IllegalInstructionException> { gen.addPacketCopyFromR0LenR1() }
        assertFailsWith<IllegalInstructionException> { gen.addDataCopyFromR0LenR1() }
        assertFailsWith<IllegalInstructionException> { gen.addPacketCopyFromR0(10) }
        assertFailsWith<IllegalInstructionException> { gen.addDataCopyFromR0(10) }
        assertFailsWith<IllegalInstructionException> {
            gen.addJumpIfBytesAtR0Equal(byteArrayOf('A'.code.toByte()), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalInstructionException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte()), 0x0c, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalInstructionException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte()), 0x0c, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalInstructionException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'A'.code.toByte()), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalInstructionException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'A'.code.toByte()), ApfV4Generator.DROP_LABEL) }
    }

    @Test
    fun testDataInstructionMustComeFirst() {
        var gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addAllocateR0()
        assertFailsWith<IllegalInstructionException> { gen.addData(ByteArray(3) { 0x01 }) }
    }

    @Test
    fun testApfInstructionEncodingSizeCheck() {
        var gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        assertFailsWith<IllegalArgumentException> { gen.addAllocate(65536) }
        assertFailsWith<IllegalArgumentException> { gen.addAllocate(-1) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopy(-1, 1) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopy(-1, 1) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopy(1, 256) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopy(1, 256) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopy(1, -1) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopy(1, -1) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopyFromR0(256) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopyFromR0(256) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopyFromR0(-1) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopyFromR0(-1) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 0, 0), 256, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0), 0x0c, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, '.'.code.toByte(), 0, 0), 0x0c, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(0, 0), 0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte()), 0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 0, 0), 256, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0), 0x0c, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, '.'.code.toByte(), 0, 0), 0x0c, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(0, 0), 0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte()), 0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                0xc0, ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, '.'.code.toByte(), 0, 0), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(0, 0), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'A'.code.toByte()), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                 ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, '.'.code.toByte(), 0, 0), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(0, 0), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'A'.code.toByte()), ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                ApfV4Generator.DROP_LABEL) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                ApfV4Generator.DROP_LABEL) }
    }

    @Test
    fun testApfInstructionsEncoding() {
        var gen = ApfV4Generator(MIN_APF_VERSION)
        gen.addPass()
        var program = gen.generate()
        // encoding PASS opcode: opcode=0, imm_len=0, R=0
        assertContentEquals(
                byteArrayOf(encodeInstruction(opcode = 0, immLength = 0, register = 0)), program)

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addDrop()
        program = gen.generate()
        // encoding DROP opcode: opcode=0, imm_len=0, R=1
        assertContentEquals(
                byteArrayOf(encodeInstruction(opcode = 0, immLength = 0, register = 1)), program)

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addCountAndPass(129)
        program = gen.generate()
        // encoding COUNT(PASS) opcode: opcode=0, imm_len=size_of(imm), R=0, imm=counterNumber
        assertContentEquals(
                byteArrayOf(encodeInstruction(opcode = 0, immLength = 1, register = 0),
                        0x81.toByte()), program)

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addCountAndDrop(1000)
        program = gen.generate()
        // encoding COUNT(DROP) opcode: opcode=0, imm_len=size_of(imm), R=1, imm=counterNumber
        assertContentEquals(
                byteArrayOf(encodeInstruction(opcode = 0, immLength = 2, register = 1),
                        0x03, 0xe8.toByte()), program)

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addAllocateR0()
        gen.addAllocate(1500)
        program = gen.generate()
        // encoding ALLOC opcode: opcode=21(EXT opcode number), imm=36(TRANS opcode number).
        // R=0 means length stored in R0. R=1 means the length stored in imm1.
        assertContentEquals(byteArrayOf(
                encodeInstruction(opcode = 21, immLength = 1, register = 0), 36,
                encodeInstruction(opcode = 21, immLength = 1, register = 1), 36, 0x05,
                0xDC.toByte()),
        program)
        // TODO: add back disassembling test check after we update the apf_disassembler
        // assertContentEquals(arrayOf("       0: alloc"), ApfJniUtils.disassembleApf(program))

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addTransmit()
        gen.addDiscard()
        program = gen.generate()
        // encoding TRANSMIT/DISCARD opcode: opcode=21(EXT opcode number),
        // imm=37(TRANSMIT/DISCARD opcode number),
        // R=0 means discard the buffer. R=1 means transmit the buffer.
        assertContentEquals(byteArrayOf(
                encodeInstruction(opcode = 21, immLength = 1, register = 0), 37,
                encodeInstruction(opcode = 21, immLength = 1, register = 1), 37,
        ), program)
        // TODO: add back disassembling test check after we update the apf_disassembler
        // assertContentEquals(arrayOf("       0: trans"), ApfJniUtils.disassembleApf(program))

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        val largeByteArray = ByteArray(256) { 0x01 }
        gen.addData(largeByteArray)
        program = gen.generate()
        // encoding DATA opcode: opcode=14(JMP), R=1
        assertContentEquals(byteArrayOf(
                encodeInstruction(opcode = 14, immLength = 2, register = 1), 0x01, 0x00) +
                largeByteArray, program)

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addWriteU8(0x01)
        gen.addWriteU16(0x0102)
        gen.addWriteU32(0x01020304)
        gen.addWriteU8(0x00)
        gen.addWriteU8(0x80)
        gen.addWriteU16(0x0000)
        gen.addWriteU16(0x8000)
        gen.addWriteU32(0x00000000)
        gen.addWriteU32(0x80000000)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(24, 1, 0), 0x01,
                encodeInstruction(24, 2, 0), 0x01, 0x02,
                encodeInstruction(24, 4, 0), 0x01, 0x02, 0x03, 0x04,
                encodeInstruction(24, 1, 0), 0x00,
                encodeInstruction(24, 1, 0), 0x80.toByte(),
                encodeInstruction(24, 2, 0), 0x00, 0x00,
                encodeInstruction(24, 2, 0), 0x80.toByte(), 0x00,
                encodeInstruction(24, 4, 0), 0x00, 0x00, 0x00, 0x00,
                encodeInstruction(24, 4, 0), 0x80.toByte(), 0x00, 0x00,
                0x00), program)
        assertContentEquals(arrayOf(
            "       0: write       0x01",
            "       2: write       0x0102",
            "       5: write       0x01020304",
            "      10: write       0x00",
            "      12: write       0x80",
            "      14: write       0x0000",
            "      17: write       0x8000",
            "      20: write       0x00000000",
            "      25: write       0x80000000"
        ),
        ApfJniUtils.disassembleApf(program))

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addWriteU8(R0)
        gen.addWriteU16(R0)
        gen.addWriteU32(R0)
        gen.addWriteU8(R1)
        gen.addWriteU16(R1)
        gen.addWriteU32(R1)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 38,
                encodeInstruction(21, 1, 0), 39,
                encodeInstruction(21, 1, 0), 40,
                encodeInstruction(21, 1, 1), 38,
                encodeInstruction(21, 1, 1), 39,
                encodeInstruction(21, 1, 1), 40
        ), program)
        // TODO: add back disassembling test check after we update the apf_disassembler
//        assertContentEquals(arrayOf(
//                "       0: ewrite1 r0",
//                "       2: ewrite2 r0",
//                "       4: ewrite4 r0",
//                "       6: ewrite1 r1",
//                "       8: ewrite2 r1",
//                "      10: ewrite4 r1"), ApfJniUtils.disassembleApf(program))

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addDataCopy(0, 10)
        gen.addDataCopy(1, 5)
        gen.addPacketCopy(1000, 255)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(25, 0, 1), 10,
                encodeInstruction(25, 1, 1), 1, 5,
                encodeInstruction(25, 2, 0),
                0x03.toByte(), 0xe8.toByte(), 0xff.toByte(),
        ), program)
        // TODO: add back disassembling test check after we update the apf_disassembler
//        assertContentEquals(arrayOf(
//                "       0: dcopy 0, 5",
//                "       3: pcopy 1000, 255"), ApfJniUtils.disassembleApf(program))

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addPacketCopyFromR0LenR1()
        gen.addPacketCopyFromR0(5)
        gen.addDataCopyFromR0LenR1()
        gen.addDataCopyFromR0(5)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 1), 41,
                encodeInstruction(21, 1, 0), 41, 5,
                encodeInstruction(21, 1, 1), 42,
                encodeInstruction(21, 1, 0), 42, 5,
        ), program)
        // TODO: add back the following test case when implementing EPKTCOPY, EDATACOPY opcodes.
//        assertContentEquals(arrayOf(
//                "       0: dcopy [r1+0], 5",
//                "       4: pcopy [r0+1000], 255"), ApfJniUtils.disassembleApf(program))

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addJumpIfBytesAtR0Equal(byteArrayOf('a'.code.toByte()), ApfV4Generator.DROP_LABEL)
        program = gen.generate()
        assertContentEquals(
                byteArrayOf(encodeInstruction(opcode = 20, immLength = 1, register = 1),
                        1, 1, 'a'.code.toByte()), program)

        val qnames = byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0, 0)
        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addJumpIfPktAtR0DoesNotContainDnsQ(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
        gen.addJumpIfPktAtR0ContainDnsQ(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 43, 11, 0x0c.toByte(),
        ) + qnames + byteArrayOf(
                encodeInstruction(21, 1, 1), 43, 1, 0x0c.toByte(),
        ) + qnames, program)

        gen = ApfV4Generator(MIN_APF_VERSION_IN_DEV)
        gen.addJumpIfPktAtR0DoesNotContainDnsA(qnames, ApfV4Generator.DROP_LABEL)
        gen.addJumpIfPktAtR0ContainDnsA(qnames, ApfV4Generator.DROP_LABEL)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 44, 10,
        ) + qnames + byteArrayOf(
                encodeInstruction(21, 1, 1), 44, 1,
        ) + qnames, program)
    }

    private fun encodeInstruction(opcode: Int, immLength: Int, register: Int): Byte {
        val immLengthEncoding = if (immLength == 4) 3 else immLength
        return opcode.shl(3).or(immLengthEncoding.shl(1)).or(register).toByte()
    }
}
