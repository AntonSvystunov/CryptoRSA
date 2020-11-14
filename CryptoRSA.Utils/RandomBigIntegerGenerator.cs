using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace CryptoRSA.Utils
{
    public class RandomBigIntegerGenerator: IDisposable
    {
        private readonly RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();

        public void Dispose()
        {
            ((IDisposable)randomNumberGenerator).Dispose();
        }

        public BigInteger GetBigInteger(BigInteger max, BigInteger min)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger res;

            do
            {
                randomNumberGenerator.GetBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F;
                res = new BigInteger(bytes);
            } while (res >= max || res <= min);

            return res;
        }

        public BigInteger GetBigInteger(BigInteger max)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger res;

            do
            {
                randomNumberGenerator.GetBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F;
                res = new BigInteger(bytes);
            } while (res >= max);

            return res;
        }

        public BigInteger GetBigInteger(int length)
        {
            byte[] bytes = new byte[length];
            randomNumberGenerator.GetBytes(bytes);
            bytes[bytes.Length - 1] &= (byte)0x7F;
            return new BigInteger(bytes);
        }
    }
}
