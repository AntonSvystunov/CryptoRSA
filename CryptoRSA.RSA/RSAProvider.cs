using CryptoHash.SHA256C;
using CryptoRSA.Utils;
using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace CryptoRSA.RSA
{
    public class RSAProvider: AsymmetricAlgorithm
    {
        /*
            D	d, the private exponent	privateExponent
            DP	d mod (p - 1)	exponent1
            DQ	d mod (q - 1)	exponent2
            Exponent	e, the public exponent	publicExponent
            InverseQ	(InverseQ)(q) = 1 mod p	coefficient
            Modulus	n	modulus
            P	p	prime1
            Q	q	prime2
         */
        public struct RsaParameters
        {
            public BigInteger D;
            public BigInteger P;
            public BigInteger Q;
            public BigInteger Exponent;
            public BigInteger Modulus;
            public BigInteger InverseQ;
            public BigInteger Dp;
            public BigInteger Dq;
        }

        protected RsaParameters rsaParameters;
        protected MillerRabin millerRabin;

        protected readonly KeySizes[] keySizes = { new KeySizes(8, 1024, 8) };
        public override int KeySize
        {
            get { return KeySizeValue; }
            set
            {
                for (int i = 0; i < keySizes.Length; i++)
                {
                    if (keySizes[i].SkipSize == 0)
                    {
                        if (keySizes[i].MinSize == value)
                        {
                            KeySizeValue = value;
                            return;
                        }
                    }
                    else
                    {
                        for (int j = keySizes[i].MinSize;
                            j <= keySizes[i].MaxSize;
                            j += keySizes[i].SkipSize)
                        {
                            if (j == value)
                            {
                                KeySizeValue = value;
                                return;
                            }
                        }
                    }
                }

                throw new CryptographicException("Invalid key size.");
            }
        }

        public bool DecryptDirect { get; set; } = false;

        public int HashOutputSize => 32;

        public RSAProvider()
        {
            KeySize = 256;
        }

        public RSAProvider(int keySize)
        {
            KeySize = keySize;
        }

        public RSAProvider(RsaParameters parameters)
        {
            rsaParameters = parameters;
        }

        public void InitializeParameters()
        {
            millerRabin = new MillerRabin();
            BigInteger p = millerRabin.GetRandomPrime(KeySize / 8);
            BigInteger q = millerRabin.GetRandomPrime(KeySize / 8);
            

            BigInteger fi = (p - 1) * (q - 1);
            BigInteger e = millerRabin.GetRandomPrime(fi);

            BigInteger d = BigIntegerExtensions.ModInverse(e, fi);
            BigInteger inverseQ = BigIntegerExtensions.ModInverse(q, p);
            BigInteger dp = d % (p - 1);
            BigInteger dq = d % (q - 1);

            rsaParameters = new RsaParameters
            {
                P = p,
                Q = q,
                Modulus = (p * q),
                Exponent = e,
                Dp = dp,
                Dq = dq,
                InverseQ = inverseQ,
                D = d
            };
        }

        public byte[] Encrypt(byte[] rgb, bool fOAEP)
        {
            BigInteger message = fOAEP ? FromBigEndian(OAEPEncrypt(rgb)) : FromBigEndian(rgb);
            var cipher = CoreEncrypt(message);
            return ToBigEndian(cipher);
        }

        private BigInteger CoreEncrypt(BigInteger m)
        {
            return BigInteger.ModPow(m, rsaParameters.Exponent, rsaParameters.Modulus);
        }

        private byte[] OAEPEncrypt(byte[] message)
        {
            var modLen = rsaParameters.Modulus.GetByteCount();

            byte[] r = new byte[HashOutputSize];
            RandomNumberGenerator.Fill(r);

            var msize = modLen - r.Length - 1;
            var m = new byte[msize];
            m.Initialize();
            Array.Copy(message, m, message.Length);

            using var sha256 = new SHA256C();
            var X = XorArray(m, sha256.ComputeHash(r));
            sha256.Initialize();
            var Y = XorArray(r, sha256.ComputeHash(X));

            return X.Concat(Y).ToArray();
        }

        private byte[] OAEPDecrypt(byte[] cipher)
        {
            var modLen = rsaParameters.Modulus.GetByteCount();

            var msize = modLen - HashOutputSize - 1;

            var X = new byte[msize];
            var Y = new byte[HashOutputSize];

            Array.Copy(cipher, 0, X, 0, msize);
            Array.Copy(cipher, msize, Y, 0, Y.Length);

            using var sha256 = new SHA256C();
            var r = XorArray(Y, sha256.ComputeHash(X));
            sha256.Initialize();
            var m = XorArray(X, sha256.ComputeHash(r));

            var i = m.Length - 1;
            while (m[i] == 0)
            {
                --i;
            }

            return m.Take(i + 1).ToArray();
        }

        private byte[] XorArray(byte[] a, byte[] b)
        {
            var result = (byte[])a.Clone();
            for (int i = 0; i < b.Length; i++)
            {
                result[i] ^= b[i];
            }
            return result;
        }

        private BigInteger CoreDecrypt(BigInteger c, bool direct = false)
        {
            if (direct)
            {
                return BigInteger.ModPow(c, rsaParameters.D, rsaParameters.Modulus);
            }

            BigInteger m1 = BigInteger.ModPow(c, rsaParameters.Dp, rsaParameters.P);
            BigInteger m2 = BigInteger.ModPow(c, rsaParameters.Dq, rsaParameters.Q);

            BigInteger h = (rsaParameters.InverseQ * (m1 - m2)) % rsaParameters.P;
            BigInteger m = (m2 + h * rsaParameters.Q) % rsaParameters.Modulus;

            return m;
        }

        public byte[] Decrypt(byte[] rgb, bool fOAEP)
        {
            var cipher = FromBigEndian(rgb);
            var message = CoreDecrypt(cipher, DecryptDirect);
            var result = ToBigEndian(message);

            if (fOAEP)
            {
                result = OAEPDecrypt(result);
            }

            return result;
        }

        public RsaParameters GetParameters()
        {
            return rsaParameters;
        }

        public new void Dispose()
        {
            base.Dispose();
            ((IDisposable)millerRabin).Dispose();
        }

        private static BigInteger FromBigEndian(byte[] bytes)
        {
            var reversed = new byte[bytes.Length];
            Array.Copy(bytes, reversed, bytes.Length);
            Array.Reverse(reversed);
            return new BigInteger(reversed);
        }

        private static byte[] ToBigEndian(BigInteger a)
        {
            var bytes = a.ToByteArray();
            var reversed = new byte[bytes.Length];
            Array.Copy(bytes, reversed, bytes.Length);
            Array.Reverse(reversed);
            return reversed;
        }
    }
}
