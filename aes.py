import os
import secrets

def generate_key(size):
    return secrets.token_hex(size)

def pad(block):
    number = 16 - (len(block) // 2)
    for i in range(number):
        block += format(number, "02x")

    return block

def unpad(block):
    number = int(block[-2:], 16)
    return block[:-number*2]

class AES:
    Sbox = (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16)

    Sbox_inv = (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D)

    nb = 4

    rcon = 0x01

    def __init__(self, key):
        if (len(key) // 2) == 16:
            self.nk = 4
            self.nr = 10
            self.number_of_words = 44
            self.key = self.get_state(key)
        elif (len(key) // 2) == 24:
            self.nk = 6
            self.nr = 12
            self.number_of_words = 52
            self.key = self.get_state(key, 24)
        else:
            self.nk = 8
            self.nr = 14
            self.number_of_words = 60
            self.key = self.get_state(key, 32)

        self.key_schedule = self.key_expansion(self.key)

    def get_state(self, text, lenght=16):
        state = []
        temp = []
        for i in range(lenght):
            if i % 4 == 0 and i != 0:
                state.append(temp.copy())
                temp.clear()
                temp.append(int(text[i*2:i*2+2], 16))
            else:
                temp.append(int(text[i*2:i*2+2], 16))

        state.append(temp)

        return state

    def rot_word(self, word):
        return word[1:] + word[:1]

    def key_expansion(self, key):
        self.round_keys = key

        for i in range(self.nk, self.number_of_words):
            self.round_keys.append([0, 0, 0, 0])
            temp = self.round_keys[i-1][:]
            if i % self.nk == 0:
                temp = self.rot_word(temp)
                self.sub_bytes(temp)
                temp[0] = temp[0] ^ self.rcon
                self.rcon *= 2

                if self.rcon == 256:
                    self.rcon = 27

            elif self.nk == 8 and i % self.nk == 4:
                self.sub_bytes(temp)

            for j in range(4):
                self.round_keys[i][j] = self.round_keys[i-self.nk][j] ^ temp[j]

        return self.round_keys

    def sub_bytes(self, word):
        for i in range(len(word)):
            word[i] = self.Sbox[word[i]]

    def inv_sub_bytes(self, word):
        for i in range(len(word)):
            word[i] = self.Sbox_inv[word[i]]

    def encrypt(self, block):

        number_of_key = 4
        state = self.get_state(block)
        new_state = self.add_round_key(state, self.key_schedule[0:number_of_key])

        for i in range(self.nr-1):

            for j in range(self.nb):
                self.sub_bytes(new_state[j])
            self.shift_rows(new_state)
            self.mix_columns(new_state)
            new_state = self.add_round_key(new_state, self.key_schedule[number_of_key:number_of_key+4])
            number_of_key += 4

        for j in range(self.nb):
            self.sub_bytes(new_state[j])
        self.shift_rows(new_state)
        new_state = self.add_round_key(new_state, self.key_schedule[number_of_key:number_of_key + 4])

        result = ""
        for bytes in new_state:
            for byte in bytes:
                if byte < 16:
                    number = str(hex(byte))[2:]
                    result += "0" + number
                else:
                    result += str(hex(byte))[2:]

        return result

    def decrypt(self, block):

        number_of_key = len(self.key_schedule)
        state = self.get_state(block)
        new_state = self.add_round_key(state, self.key_schedule[number_of_key-4:number_of_key])
        number_of_key -= 4

        for i in range(self.nr-1):

            self.inv_shift_rows(new_state)
            for j in range(self.nb):
                self.inv_sub_bytes(new_state[j])
            new_state = self.add_round_key(new_state, self.key_schedule[number_of_key-4:number_of_key])
            self.invMixColumns(new_state)
            number_of_key -= 4

        for j in range(self.nb):
            self.inv_sub_bytes(new_state[j])
        self.inv_shift_rows(new_state)
        new_state = self.add_round_key(new_state, self.key_schedule[number_of_key-4:number_of_key])

        result = ""
        for bytes in new_state:
            for byte in bytes:
                value = str(hex(byte))[2:]
                if len(value) == 1:
                    value = "0" + value
                result += value

        return result

    def add_round_key(self, state, key):
        result = []
        for i in range(len(state)):
            temp = []
            for j in range(len(state)):
                temp.append(state[i][j]^key[i][j])

            result.append(temp)

        return result

    def shift_rows(self, state):
        state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

    def inv_shift_rows(self, state):
        state[0][1], state[1][1], state[2][1], state[3][1] = state[3][1], state[0][1], state[1][1], state[2][1]
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[1][3], state[2][3], state[3][3], state[0][3]

    def mix_columns(self, s):
        matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]

        result = [[0 for _ in range(4)] for _ in range(4)]

        for col in range(4):
            for row in range(4):
                val = 0
                for i in range(4):
                    # Mnożenie w ciele skończonym GF(2^8)
                    if matrix[row][i] == 0x01:
                        val ^= s[i][col]
                    elif matrix[row][i] == 0x02:
                        val ^= (s[i][col] << 1)
                    elif matrix[row][i] == 0x03:
                        val ^= ((s[i][col] << 1) ^ s[i][col])

                result[row][col] = val

        return result

    def invMixColumns(self, state):
        inv_matrix = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e]
        ]

        result = [[0 for _ in range(4)] for _ in range(4)]

        for col in range(4):
            for row in range(4):
                val = 0
                for i in range(4):
                    # Mnożenie w ciele skończonym GF(2^8)
                    if inv_matrix[row][i] == 0x09:
                        val ^= (state[i][col] << 3) ^ state[i][col]
                    elif inv_matrix[row][i] == 0x0b:
                        val ^= (state[i][col] << 3) ^ (state[i][col] << 1) ^ state[i][col]
                    elif inv_matrix[row][i] == 0x0d:
                        val ^= (state[i][col] << 3) ^ (state[i][col] << 2) ^ state[i][col]
                    elif inv_matrix[row][i] == 0x0e:
                        val ^= (state[i][col] << 3) ^ (state[i][col] << 2) ^ (state[i][col] << 1)

                result[row][col] = val % 256

        return result

def encrypt_message(message, alg):
    converted_messaage = ''.join(hex(ord(c))[2:] for c in message)
    fragment = [converted_messaage[i: i + 32] for i in range(0, len(converted_messaage), 32)]

    if len(fragment[-1]) < 32:
        fragment[-1] = pad(fragment[-1])

    coded = ""
    for i in range(len(fragment)):
        coded += alg.encrypt(fragment[i])

    return coded

def decrypt_message(message, alg):
    fragment = [message[i: i + 32] for i in range(0, len(message), 32)]

    result = []
    for i in range(len(fragment)):
        result.append(alg.decrypt(fragment[i]))

    result[-1] = unpad(result[-1])

    output = ""
    for fragment in result:
        output += bytearray.fromhex(fragment).decode()
    return output

def operation_on_file(file, name, alg, encrypt=True):
    with open(file, "rb") as f:
        hex_array = []
        for offset in range(0, os.path.getsize(file), 16):
            hex_array.append(bytes.hex(f.read(16)))
            f.seek(offset + 16)

    if encrypt:
        if len(hex_array[-1]) < 32:
            hex_array[-1] = pad(hex_array[-1])

        coded_hex = []
        for fragment in hex_array:
            coded_hex.append(alg.encrypt(fragment))

    else:
        coded_hex = []
        for fragment in hex_array:
            coded_hex.append(alg.decrypt(fragment))

        coded_hex[-1] = unpad(coded_hex[-1])

    with open(name, "ab") as f:
        for i in range(len(coded_hex)):
            f.write(bytes.fromhex(coded_hex[i]))


