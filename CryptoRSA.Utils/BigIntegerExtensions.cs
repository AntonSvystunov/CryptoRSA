using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace CryptoRSA.Utils
{
    public static class BigIntegerExtensions
    {
        /*public static BigInteger Power(this BigInteger x, BigInteger y, BigInteger p)
        {
            BigInteger res = 1;
            x = x % p;
            while (y > 0)
            {
                if ((y & 1) == 1)
                    res = (res * x) % p;
                y = y >> 1;
                x = (x * x) % p;
            }
            return res;
        }*/

        public static BigInteger ModInverse(BigInteger a, BigInteger b)
        {
            BigInteger rOld = b, rNew = a, dOld = 0, dNew = 1;
            while (rNew > 0)
            {
                BigInteger t = rOld / rNew, x = rNew;
                rNew = rOld % x;
                rOld = x;
                x = dNew;
                dNew = dOld - t * x;
                dOld = x;
            }

            dOld %= b;
            if (dOld < 0)
            {
                dOld = (dOld + b) % b;
            }
            return dOld;
        }
    }
}
