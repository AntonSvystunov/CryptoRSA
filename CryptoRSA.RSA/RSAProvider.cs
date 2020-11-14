using CryptoRSA.Utils;
using System;
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
            var message = FromBigEndian(rgb);
            var cipher = CoreEncrypt(message);
            return ToBigEndian(cipher);
        }

        private BigInteger CoreEncrypt(BigInteger m)
        {
            return BigInteger.ModPow(m, rsaParameters.Exponent, rsaParameters.Modulus);
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
            return ToBigEndian(message);
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
