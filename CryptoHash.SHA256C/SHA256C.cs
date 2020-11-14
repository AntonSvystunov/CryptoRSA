using System;
using System.Security.Cryptography;

namespace CryptoHash.SHA256C
{
    public class SHA256C : HashAlgorithm
    {
        private byte[] _buffer;
        private long _count;

        private uint[] _state;
        private uint[] _words;

        public SHA256C()
        {
            HashSizeValue = 256;
            _buffer = new byte[64];
            _state = new uint[8];
            _words = new uint[64];
            SetInitialStateValues();
        }

        public override void Initialize()
        {            
            Array.Clear(_buffer, 0, _buffer.Length);
            Array.Clear(_words, 0, _words.Length); 
            SetInitialStateValues();
        }

        private void SetInitialStateValues()
        {
            _count = 0;

            _state[0] = 0x6a09e667;
            _state[1] = 0xbb67ae85;
            _state[2] = 0x3c6ef372;
            _state[3] = 0xa54ff53a;
            _state[4] = 0x510e527f;
            _state[5] = 0x9b05688c;
            _state[6] = 0x1f83d9ab;
            _state[7] = 0x5be0cd19;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            HashBytes(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            byte[] hash = new byte[32];
            int buffPos = (int)_count & 0X3F;

            int blockLen = 64 - buffPos;
            if (blockLen <= 8)
            {
                blockLen += 64;
            }

            byte[] paddingBlock = new byte[blockLen];


            long bitCount = _count * 8;
            paddingBlock[0] = 0x80;

            paddingBlock[blockLen - 8] = (byte)((bitCount >> 56) & 0xff);
            paddingBlock[blockLen - 7] = (byte)((bitCount >> 48) & 0xff);
            paddingBlock[blockLen - 6] = (byte)((bitCount >> 40) & 0xff);
            paddingBlock[blockLen - 5] = (byte)((bitCount >> 32) & 0xff);
            paddingBlock[blockLen - 4] = (byte)((bitCount >> 24) & 0xff);
            paddingBlock[blockLen - 3] = (byte)((bitCount >> 16) & 0xff);
            paddingBlock[blockLen - 2] = (byte)((bitCount >> 8) & 0xff);
            paddingBlock[blockLen - 1] = (byte)((bitCount >> 0) & 0xff);

            HashBytes(paddingBlock, 0, paddingBlock.Length);

            UInt32WordToBigEndian(_state, 8, hash);
            HashValue = hash;
            return hash;
        }

        private void HashBytes(byte[] array, int offset, int size)
        {
            int inOffset = offset;
            int inSize = size;
            int buffPos = (int)_count & 0X3F;

            _count += size;

            if (buffPos > 0 && (buffPos + inSize) >= 64)
            {
                Buffer.BlockCopy(array, inOffset, _buffer, buffPos, 64 - buffPos);
                inOffset += 64 - buffPos;
                inSize -= 64 - buffPos;
                Transform(_buffer, _state);
            } 

            while (inSize >= 64)
            {
                Buffer.BlockCopy(array, inOffset, _buffer, 0, 64);
                inOffset += 64;
                inSize -= 64;
                Transform(_buffer, _state);
            }

            if (inSize > 0)
            {
                Buffer.BlockCopy(array, inOffset, _buffer, 0, inSize);
            }
        }

        private readonly static uint[] _k = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private static void Transform(byte[] block, uint[] state)
        {
            uint a = state[0],
                 b = state[1],
                 c = state[2],
                 d = state[3],
                 e = state[4],
                 f = state[5],
                 g = state[6],
                 h = state[7];

            uint[] words = new uint[64];
            UInt32WordFromBigEndian(block, words, 16);
            ExpandWords(words);

            uint T1, T2;
            for (uint i = 0; i < 64; i++)
            {
                T1 = h + Sigma1(e) + Ch(e, f, g) + _k[i] + words[i];
                T2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;                
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        private static void UInt32WordFromBigEndian(byte[] bytes, uint[] words, int digits)
        {
            if (bytes.Length * 4 < digits)
            {
                throw new ArgumentException($"{nameof(words)} bit size is less than {nameof(bytes)}");
            }

            for (int i = 0, j = 0; i < digits; i++, j += 4)
            {
                words[i] = (uint)((bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3]);
            }
        }

        private static void UInt32WordToBigEndian(uint[] words, int digits, byte[] bytes)
        {
            if (bytes.Length * 4 < digits)
            {
                throw new ArgumentException($"{nameof(words)} bit size is less than {nameof(bytes)}");
            }

            for (int i = 0, j = 0; i < digits; i++, j += 4)
            {
                bytes[j] = (byte)((words[i] >> 24) & 0xff);
                bytes[j + 1] = (byte)((words[i] >> 16) & 0xff);
                bytes[j + 2] = (byte)((words[i] >> 8) & 0xff);
                bytes[j + 3] = (byte)(words[i] & 0xff);
            }
        }

        private static uint RotateRight(uint x, int n)
        {
            return (((x) >> (n)) | ((x) << (32 - (n))));
        }

        private static uint Ch(uint x, uint y, uint z)
        {
            return ((x & y) ^ ((x ^ 0xffffffff) & z));
        }

        private static uint Maj(uint x, uint y, uint z)
        {
            return ((x & y) ^ (x & z) ^ (y & z));
        }

        private static uint S0(uint x)
        {
            return (RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3));
        }

        private static uint S1(uint x)
        {
            return (RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10));
        }

        private static uint Sigma0(uint x)
        {
            return (RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22));
        }

        private static uint Sigma1(uint x)
        {
            return (RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25));
        }

        private static void ExpandWords(uint[] words)
        {
            if (words.Length != 64)
                throw new ArgumentException("W array length should be equal to 64");

            for (int i = 16; i < 64; i++)
            {
                words[i] = S1(words[i - 2]) + words[i - 7] + S0(words[i - 15]) + words[i - 16];
            }
        }
    }
}
