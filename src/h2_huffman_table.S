// Auto-generated from RFC 7541 Appendix B — the HPACK static
// Huffman code. 257 entries (symbols 0-255 plus EOS 256),
// sorted by (code length, code). Each entry is 8 bytes: the code
// as a u32 (aligned to the LSB) and the symbol as a u32, so the
// decoder can scan only the entries whose length matches the
// number of bits accumulated so far.
.align 2
h2_huffman_table:
    .word 0x00000000  // symbol 48 (0), 5 bits
    .word 48
    .word 0x00000001  // symbol 49 (1), 5 bits
    .word 49
    .word 0x00000002  // symbol 50 (2), 5 bits
    .word 50
    .word 0x00000003  // symbol 97 (a), 5 bits
    .word 97
    .word 0x00000004  // symbol 99 (c), 5 bits
    .word 99
    .word 0x00000005  // symbol 101 (e), 5 bits
    .word 101
    .word 0x00000006  // symbol 105 (i), 5 bits
    .word 105
    .word 0x00000007  // symbol 111 (o), 5 bits
    .word 111
    .word 0x00000008  // symbol 115 (s), 5 bits
    .word 115
    .word 0x00000009  // symbol 116 (t), 5 bits
    .word 116
    .word 0x00000014  // symbol 32 ( ), 6 bits
    .word 32
    .word 0x00000015  // symbol 37 (%), 6 bits
    .word 37
    .word 0x00000016  // symbol 45 (-), 6 bits
    .word 45
    .word 0x00000017  // symbol 46 (.), 6 bits
    .word 46
    .word 0x00000018  // symbol 47 (/), 6 bits
    .word 47
    .word 0x00000019  // symbol 51 (3), 6 bits
    .word 51
    .word 0x0000001a  // symbol 52 (4), 6 bits
    .word 52
    .word 0x0000001b  // symbol 53 (5), 6 bits
    .word 53
    .word 0x0000001c  // symbol 54 (6), 6 bits
    .word 54
    .word 0x0000001d  // symbol 55 (7), 6 bits
    .word 55
    .word 0x0000001e  // symbol 56 (8), 6 bits
    .word 56
    .word 0x0000001f  // symbol 57 (9), 6 bits
    .word 57
    .word 0x00000020  // symbol 61 (=), 6 bits
    .word 61
    .word 0x00000021  // symbol 65 (A), 6 bits
    .word 65
    .word 0x00000022  // symbol 95 (_), 6 bits
    .word 95
    .word 0x00000023  // symbol 98 (b), 6 bits
    .word 98
    .word 0x00000024  // symbol 100 (d), 6 bits
    .word 100
    .word 0x00000025  // symbol 102 (f), 6 bits
    .word 102
    .word 0x00000026  // symbol 103 (g), 6 bits
    .word 103
    .word 0x00000027  // symbol 104 (h), 6 bits
    .word 104
    .word 0x00000028  // symbol 108 (l), 6 bits
    .word 108
    .word 0x00000029  // symbol 109 (m), 6 bits
    .word 109
    .word 0x0000002a  // symbol 110 (n), 6 bits
    .word 110
    .word 0x0000002b  // symbol 112 (p), 6 bits
    .word 112
    .word 0x0000002c  // symbol 114 (r), 6 bits
    .word 114
    .word 0x0000002d  // symbol 117 (u), 6 bits
    .word 117
    .word 0x0000005c  // symbol 58 (:), 7 bits
    .word 58
    .word 0x0000005d  // symbol 66 (B), 7 bits
    .word 66
    .word 0x0000005e  // symbol 67 (C), 7 bits
    .word 67
    .word 0x0000005f  // symbol 68 (D), 7 bits
    .word 68
    .word 0x00000060  // symbol 69 (E), 7 bits
    .word 69
    .word 0x00000061  // symbol 70 (F), 7 bits
    .word 70
    .word 0x00000062  // symbol 71 (G), 7 bits
    .word 71
    .word 0x00000063  // symbol 72 (H), 7 bits
    .word 72
    .word 0x00000064  // symbol 73 (I), 7 bits
    .word 73
    .word 0x00000065  // symbol 74 (J), 7 bits
    .word 74
    .word 0x00000066  // symbol 75 (K), 7 bits
    .word 75
    .word 0x00000067  // symbol 76 (L), 7 bits
    .word 76
    .word 0x00000068  // symbol 77 (M), 7 bits
    .word 77
    .word 0x00000069  // symbol 78 (N), 7 bits
    .word 78
    .word 0x0000006a  // symbol 79 (O), 7 bits
    .word 79
    .word 0x0000006b  // symbol 80 (P), 7 bits
    .word 80
    .word 0x0000006c  // symbol 81 (Q), 7 bits
    .word 81
    .word 0x0000006d  // symbol 82 (R), 7 bits
    .word 82
    .word 0x0000006e  // symbol 83 (S), 7 bits
    .word 83
    .word 0x0000006f  // symbol 84 (T), 7 bits
    .word 84
    .word 0x00000070  // symbol 85 (U), 7 bits
    .word 85
    .word 0x00000071  // symbol 86 (V), 7 bits
    .word 86
    .word 0x00000072  // symbol 87 (W), 7 bits
    .word 87
    .word 0x00000073  // symbol 89 (Y), 7 bits
    .word 89
    .word 0x00000074  // symbol 106 (j), 7 bits
    .word 106
    .word 0x00000075  // symbol 107 (k), 7 bits
    .word 107
    .word 0x00000076  // symbol 113 (q), 7 bits
    .word 113
    .word 0x00000077  // symbol 118 (v), 7 bits
    .word 118
    .word 0x00000078  // symbol 119 (w), 7 bits
    .word 119
    .word 0x00000079  // symbol 120 (x), 7 bits
    .word 120
    .word 0x0000007a  // symbol 121 (y), 7 bits
    .word 121
    .word 0x0000007b  // symbol 122 (z), 7 bits
    .word 122
    .word 0x000000f8  // symbol 38 (&), 8 bits
    .word 38
    .word 0x000000f9  // symbol 42 (*), 8 bits
    .word 42
    .word 0x000000fa  // symbol 44 (,), 8 bits
    .word 44
    .word 0x000000fb  // symbol 59 (;), 8 bits
    .word 59
    .word 0x000000fc  // symbol 88 (X), 8 bits
    .word 88
    .word 0x000000fd  // symbol 90 (Z), 8 bits
    .word 90
    .word 0x000003f8  // symbol 33 (!), 10 bits
    .word 33
    .word 0x000003f9  // symbol 34 ("), 10 bits
    .word 34
    .word 0x000003fa  // symbol 40 ((), 10 bits
    .word 40
    .word 0x000003fb  // symbol 41 ()), 10 bits
    .word 41
    .word 0x000003fc  // symbol 63 (?), 10 bits
    .word 63
    .word 0x000007fa  // symbol 39 ('), 11 bits
    .word 39
    .word 0x000007fb  // symbol 43 (+), 11 bits
    .word 43
    .word 0x000007fc  // symbol 124 (|), 11 bits
    .word 124
    .word 0x00000ffa  // symbol 35 (#), 12 bits
    .word 35
    .word 0x00000ffb  // symbol 62 (>), 12 bits
    .word 62
    .word 0x00001ff8  // symbol 0 (.), 13 bits
    .word 0
    .word 0x00001ff9  // symbol 36 ($), 13 bits
    .word 36
    .word 0x00001ffa  // symbol 64 (@), 13 bits
    .word 64
    .word 0x00001ffb  // symbol 91 ([), 13 bits
    .word 91
    .word 0x00001ffc  // symbol 93 (]), 13 bits
    .word 93
    .word 0x00001ffd  // symbol 126 (~), 13 bits
    .word 126
    .word 0x00003ffc  // symbol 94 (^), 14 bits
    .word 94
    .word 0x00003ffd  // symbol 125 (}), 14 bits
    .word 125
    .word 0x00007ffc  // symbol 60 (<), 15 bits
    .word 60
    .word 0x00007ffd  // symbol 96 (`), 15 bits
    .word 96
    .word 0x00007ffe  // symbol 123 ({), 15 bits
    .word 123
    .word 0x0007fff0  // symbol 92 (\), 19 bits
    .word 92
    .word 0x0007fff1  // symbol 195 (.), 19 bits
    .word 195
    .word 0x0007fff2  // symbol 208 (.), 19 bits
    .word 208
    .word 0x000fffe6  // symbol 128 (.), 20 bits
    .word 128
    .word 0x000fffe7  // symbol 130 (.), 20 bits
    .word 130
    .word 0x000fffe8  // symbol 131 (.), 20 bits
    .word 131
    .word 0x000fffe9  // symbol 162 (.), 20 bits
    .word 162
    .word 0x000fffea  // symbol 184 (.), 20 bits
    .word 184
    .word 0x000fffeb  // symbol 194 (.), 20 bits
    .word 194
    .word 0x000fffec  // symbol 224 (.), 20 bits
    .word 224
    .word 0x000fffed  // symbol 226 (.), 20 bits
    .word 226
    .word 0x001fffdc  // symbol 153 (.), 21 bits
    .word 153
    .word 0x001fffdd  // symbol 161 (.), 21 bits
    .word 161
    .word 0x001fffde  // symbol 167 (.), 21 bits
    .word 167
    .word 0x001fffdf  // symbol 172 (.), 21 bits
    .word 172
    .word 0x001fffe0  // symbol 176 (.), 21 bits
    .word 176
    .word 0x001fffe1  // symbol 177 (.), 21 bits
    .word 177
    .word 0x001fffe2  // symbol 179 (.), 21 bits
    .word 179
    .word 0x001fffe3  // symbol 209 (.), 21 bits
    .word 209
    .word 0x001fffe4  // symbol 216 (.), 21 bits
    .word 216
    .word 0x001fffe5  // symbol 217 (.), 21 bits
    .word 217
    .word 0x001fffe6  // symbol 227 (.), 21 bits
    .word 227
    .word 0x001fffe7  // symbol 229 (.), 21 bits
    .word 229
    .word 0x001fffe8  // symbol 230 (.), 21 bits
    .word 230
    .word 0x003fffd2  // symbol 129 (.), 22 bits
    .word 129
    .word 0x003fffd3  // symbol 132 (.), 22 bits
    .word 132
    .word 0x003fffd4  // symbol 133 (.), 22 bits
    .word 133
    .word 0x003fffd5  // symbol 134 (.), 22 bits
    .word 134
    .word 0x003fffd6  // symbol 136 (.), 22 bits
    .word 136
    .word 0x003fffd7  // symbol 146 (.), 22 bits
    .word 146
    .word 0x003fffd8  // symbol 154 (.), 22 bits
    .word 154
    .word 0x003fffd9  // symbol 156 (.), 22 bits
    .word 156
    .word 0x003fffda  // symbol 160 (.), 22 bits
    .word 160
    .word 0x003fffdb  // symbol 163 (.), 22 bits
    .word 163
    .word 0x003fffdc  // symbol 164 (.), 22 bits
    .word 164
    .word 0x003fffdd  // symbol 169 (.), 22 bits
    .word 169
    .word 0x003fffde  // symbol 170 (.), 22 bits
    .word 170
    .word 0x003fffdf  // symbol 173 (.), 22 bits
    .word 173
    .word 0x003fffe0  // symbol 178 (.), 22 bits
    .word 178
    .word 0x003fffe1  // symbol 181 (.), 22 bits
    .word 181
    .word 0x003fffe2  // symbol 185 (.), 22 bits
    .word 185
    .word 0x003fffe3  // symbol 186 (.), 22 bits
    .word 186
    .word 0x003fffe4  // symbol 187 (.), 22 bits
    .word 187
    .word 0x003fffe5  // symbol 189 (.), 22 bits
    .word 189
    .word 0x003fffe6  // symbol 190 (.), 22 bits
    .word 190
    .word 0x003fffe7  // symbol 196 (.), 22 bits
    .word 196
    .word 0x003fffe8  // symbol 198 (.), 22 bits
    .word 198
    .word 0x003fffe9  // symbol 228 (.), 22 bits
    .word 228
    .word 0x003fffea  // symbol 232 (.), 22 bits
    .word 232
    .word 0x003fffeb  // symbol 233 (.), 22 bits
    .word 233
    .word 0x007fffd8  // symbol 1 (.), 23 bits
    .word 1
    .word 0x007fffd9  // symbol 135 (.), 23 bits
    .word 135
    .word 0x007fffda  // symbol 137 (.), 23 bits
    .word 137
    .word 0x007fffdb  // symbol 138 (.), 23 bits
    .word 138
    .word 0x007fffdc  // symbol 139 (.), 23 bits
    .word 139
    .word 0x007fffdd  // symbol 140 (.), 23 bits
    .word 140
    .word 0x007fffde  // symbol 141 (.), 23 bits
    .word 141
    .word 0x007fffdf  // symbol 143 (.), 23 bits
    .word 143
    .word 0x007fffe0  // symbol 147 (.), 23 bits
    .word 147
    .word 0x007fffe1  // symbol 149 (.), 23 bits
    .word 149
    .word 0x007fffe2  // symbol 150 (.), 23 bits
    .word 150
    .word 0x007fffe3  // symbol 151 (.), 23 bits
    .word 151
    .word 0x007fffe4  // symbol 152 (.), 23 bits
    .word 152
    .word 0x007fffe5  // symbol 155 (.), 23 bits
    .word 155
    .word 0x007fffe6  // symbol 157 (.), 23 bits
    .word 157
    .word 0x007fffe7  // symbol 158 (.), 23 bits
    .word 158
    .word 0x007fffe8  // symbol 165 (.), 23 bits
    .word 165
    .word 0x007fffe9  // symbol 166 (.), 23 bits
    .word 166
    .word 0x007fffea  // symbol 168 (.), 23 bits
    .word 168
    .word 0x007fffeb  // symbol 174 (.), 23 bits
    .word 174
    .word 0x007fffec  // symbol 175 (.), 23 bits
    .word 175
    .word 0x007fffed  // symbol 180 (.), 23 bits
    .word 180
    .word 0x007fffee  // symbol 182 (.), 23 bits
    .word 182
    .word 0x007fffef  // symbol 183 (.), 23 bits
    .word 183
    .word 0x007ffff0  // symbol 188 (.), 23 bits
    .word 188
    .word 0x007ffff1  // symbol 191 (.), 23 bits
    .word 191
    .word 0x007ffff2  // symbol 197 (.), 23 bits
    .word 197
    .word 0x007ffff3  // symbol 231 (.), 23 bits
    .word 231
    .word 0x007ffff4  // symbol 239 (.), 23 bits
    .word 239
    .word 0x00ffffea  // symbol 9 (.), 24 bits
    .word 9
    .word 0x00ffffeb  // symbol 142 (.), 24 bits
    .word 142
    .word 0x00ffffec  // symbol 144 (.), 24 bits
    .word 144
    .word 0x00ffffed  // symbol 145 (.), 24 bits
    .word 145
    .word 0x00ffffee  // symbol 148 (.), 24 bits
    .word 148
    .word 0x00ffffef  // symbol 159 (.), 24 bits
    .word 159
    .word 0x00fffff0  // symbol 171 (.), 24 bits
    .word 171
    .word 0x00fffff1  // symbol 206 (.), 24 bits
    .word 206
    .word 0x00fffff2  // symbol 215 (.), 24 bits
    .word 215
    .word 0x00fffff3  // symbol 225 (.), 24 bits
    .word 225
    .word 0x00fffff4  // symbol 236 (.), 24 bits
    .word 236
    .word 0x00fffff5  // symbol 237 (.), 24 bits
    .word 237
    .word 0x01ffffec  // symbol 199 (.), 25 bits
    .word 199
    .word 0x01ffffed  // symbol 207 (.), 25 bits
    .word 207
    .word 0x01ffffee  // symbol 234 (.), 25 bits
    .word 234
    .word 0x01ffffef  // symbol 235 (.), 25 bits
    .word 235
    .word 0x03ffffe0  // symbol 192 (.), 26 bits
    .word 192
    .word 0x03ffffe1  // symbol 193 (.), 26 bits
    .word 193
    .word 0x03ffffe2  // symbol 200 (.), 26 bits
    .word 200
    .word 0x03ffffe3  // symbol 201 (.), 26 bits
    .word 201
    .word 0x03ffffe4  // symbol 202 (.), 26 bits
    .word 202
    .word 0x03ffffe5  // symbol 205 (.), 26 bits
    .word 205
    .word 0x03ffffe6  // symbol 210 (.), 26 bits
    .word 210
    .word 0x03ffffe7  // symbol 213 (.), 26 bits
    .word 213
    .word 0x03ffffe8  // symbol 218 (.), 26 bits
    .word 218
    .word 0x03ffffe9  // symbol 219 (.), 26 bits
    .word 219
    .word 0x03ffffea  // symbol 238 (.), 26 bits
    .word 238
    .word 0x03ffffeb  // symbol 240 (.), 26 bits
    .word 240
    .word 0x03ffffec  // symbol 242 (.), 26 bits
    .word 242
    .word 0x03ffffed  // symbol 243 (.), 26 bits
    .word 243
    .word 0x03ffffee  // symbol 255 (.), 26 bits
    .word 255
    .word 0x07ffffde  // symbol 203 (.), 27 bits
    .word 203
    .word 0x07ffffdf  // symbol 204 (.), 27 bits
    .word 204
    .word 0x07ffffe0  // symbol 211 (.), 27 bits
    .word 211
    .word 0x07ffffe1  // symbol 212 (.), 27 bits
    .word 212
    .word 0x07ffffe2  // symbol 214 (.), 27 bits
    .word 214
    .word 0x07ffffe3  // symbol 221 (.), 27 bits
    .word 221
    .word 0x07ffffe4  // symbol 222 (.), 27 bits
    .word 222
    .word 0x07ffffe5  // symbol 223 (.), 27 bits
    .word 223
    .word 0x07ffffe6  // symbol 241 (.), 27 bits
    .word 241
    .word 0x07ffffe7  // symbol 244 (.), 27 bits
    .word 244
    .word 0x07ffffe8  // symbol 245 (.), 27 bits
    .word 245
    .word 0x07ffffe9  // symbol 246 (.), 27 bits
    .word 246
    .word 0x07ffffea  // symbol 247 (.), 27 bits
    .word 247
    .word 0x07ffffeb  // symbol 248 (.), 27 bits
    .word 248
    .word 0x07ffffec  // symbol 250 (.), 27 bits
    .word 250
    .word 0x07ffffed  // symbol 251 (.), 27 bits
    .word 251
    .word 0x07ffffee  // symbol 252 (.), 27 bits
    .word 252
    .word 0x07ffffef  // symbol 253 (.), 27 bits
    .word 253
    .word 0x07fffff0  // symbol 254 (.), 27 bits
    .word 254
    .word 0x0fffffe2  // symbol 2 (.), 28 bits
    .word 2
    .word 0x0fffffe3  // symbol 3 (.), 28 bits
    .word 3
    .word 0x0fffffe4  // symbol 4 (.), 28 bits
    .word 4
    .word 0x0fffffe5  // symbol 5 (.), 28 bits
    .word 5
    .word 0x0fffffe6  // symbol 6 (.), 28 bits
    .word 6
    .word 0x0fffffe7  // symbol 7 (.), 28 bits
    .word 7
    .word 0x0fffffe8  // symbol 8 (.), 28 bits
    .word 8
    .word 0x0fffffe9  // symbol 11 (.), 28 bits
    .word 11
    .word 0x0fffffea  // symbol 12 (.), 28 bits
    .word 12
    .word 0x0fffffeb  // symbol 14 (.), 28 bits
    .word 14
    .word 0x0fffffec  // symbol 15 (.), 28 bits
    .word 15
    .word 0x0fffffed  // symbol 16 (.), 28 bits
    .word 16
    .word 0x0fffffee  // symbol 17 (.), 28 bits
    .word 17
    .word 0x0fffffef  // symbol 18 (.), 28 bits
    .word 18
    .word 0x0ffffff0  // symbol 19 (.), 28 bits
    .word 19
    .word 0x0ffffff1  // symbol 20 (.), 28 bits
    .word 20
    .word 0x0ffffff2  // symbol 21 (.), 28 bits
    .word 21
    .word 0x0ffffff3  // symbol 23 (.), 28 bits
    .word 23
    .word 0x0ffffff4  // symbol 24 (.), 28 bits
    .word 24
    .word 0x0ffffff5  // symbol 25 (.), 28 bits
    .word 25
    .word 0x0ffffff6  // symbol 26 (.), 28 bits
    .word 26
    .word 0x0ffffff7  // symbol 27 (.), 28 bits
    .word 27
    .word 0x0ffffff8  // symbol 28 (.), 28 bits
    .word 28
    .word 0x0ffffff9  // symbol 29 (.), 28 bits
    .word 29
    .word 0x0ffffffa  // symbol 30 (.), 28 bits
    .word 30
    .word 0x0ffffffb  // symbol 31 (.), 28 bits
    .word 31
    .word 0x0ffffffc  // symbol 127 (.), 28 bits
    .word 127
    .word 0x0ffffffd  // symbol 220 (.), 28 bits
    .word 220
    .word 0x0ffffffe  // symbol 249 (.), 28 bits
    .word 249
    .word 0x3ffffffc  // symbol 10 (.), 30 bits
    .word 10
    .word 0x3ffffffd  // symbol 13 (.), 30 bits
    .word 13
    .word 0x3ffffffe  // symbol 22 (.), 30 bits
    .word 22
    .word 0x3fffffff  // symbol 256 (.), 30 bits
    .word 256

// h2_huffman_len_start[32] — the table offset where each code
// length begins; the entries for length N occupy
// [h2_huffman_len_start[N], h2_huffman_len_start[N+1]).
.align 2
h2_huffman_len_start:
    .word 0  // length 0: 0 entries
    .word 0  // length 1: 0 entries
    .word 0  // length 2: 0 entries
    .word 0  // length 3: 0 entries
    .word 0  // length 4: 0 entries
    .word 0  // length 5: 10 entries
    .word 10  // length 6: 26 entries
    .word 36  // length 7: 32 entries
    .word 68  // length 8: 6 entries
    .word 74  // length 9: 0 entries
    .word 74  // length 10: 5 entries
    .word 79  // length 11: 3 entries
    .word 82  // length 12: 2 entries
    .word 84  // length 13: 6 entries
    .word 90  // length 14: 2 entries
    .word 92  // length 15: 3 entries
    .word 95  // length 16: 0 entries
    .word 95  // length 17: 0 entries
    .word 95  // length 18: 0 entries
    .word 95  // length 19: 3 entries
    .word 98  // length 20: 8 entries
    .word 106  // length 21: 13 entries
    .word 119  // length 22: 26 entries
    .word 145  // length 23: 29 entries
    .word 174  // length 24: 12 entries
    .word 186  // length 25: 4 entries
    .word 190  // length 26: 15 entries
    .word 205  // length 27: 19 entries
    .word 224  // length 28: 29 entries
    .word 253  // length 29: 0 entries
    .word 253  // length 30: 4 entries
    .word 257  // sentinel — end of the length-30 range
