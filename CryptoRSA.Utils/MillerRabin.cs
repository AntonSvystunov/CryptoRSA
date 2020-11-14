using System;
using System.Numerics;

namespace CryptoRSA.Utils
{
    public class MillerRabin: IDisposable
    {
        private readonly RandomBigIntegerGenerator _random = new RandomBigIntegerGenerator();

        public bool IsPrime(BigInteger a)
        {
            if (a <= 1 || a == 4)
            {
                return false;
            }

            if (a <= 3)
            {
                return true;
            }

            var d = a - 1;
            while (d.IsEven) d /= 2;


            var r = BigInteger.Log(a, 2);
            for (int i = 0; i < r; i++)
            {
                if (CoreTest(d, a) == false) return false;
            }

            return true;
        }

        public BigInteger GetRandomPrime(int length)
        {
            BigInteger res;
            do
            {
                res = _random.GetBigInteger(length);
            } while (!IsPrime(res));

            return res;
        }

        public BigInteger GetRandomPrime(BigInteger max)
        {
            BigInteger res;
            do
            {
                res = _random.GetBigInteger(max);
            } while (!IsPrime(res));

            return res;
        }

        private bool CoreTest(BigInteger d, BigInteger n)
        {
            BigInteger a = 2 + _random.GetBigInteger(n - 4);
            BigInteger x = BigInteger.ModPow(a, d, n);

            if (x == 1 || x == n - 1)
            {
                return true;
            }
            
            while (d != n - 1)
            {
                x = BigInteger.ModPow(x, 2, n);
                d *= 2;

                if (x == 1)
                {
                    return false;
                }
                if (x == n - 1)
                {
                    return true;
                }
            }

            return false;
        }

        public void Dispose()
        {
            ((IDisposable)_random).Dispose();
        }
    }
}
