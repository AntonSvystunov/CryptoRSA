using CryptoRSA.Utils;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace CryptoRSA
{
    class Program
    {
        static void Main(string[] args)
        {
            var hw = Encoding.UTF8.GetBytes("RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest.");

            Stopwatch sw = new Stopwatch();

            for (int i = 256; i <= 1024; i += 64)
            {
                Console.WriteLine($"\n\tRSA {i}-bits");
                using (var rsa = new RSA.RSAProvider(i))
                {
                    sw.Restart();
                    rsa.InitializeParameters();
                    sw.Stop();

                    var len = rsa.GetParameters().Modulus.GetByteCount() - 5;
                    Console.WriteLine($"Input length: {len} bytes");

                    Console.WriteLine($"KeyGen: {sw.ElapsedMilliseconds} ms.");

                    var input = hw.Take(len).ToArray();
                    sw.Restart();
                    var e = rsa.Encrypt(input, false);
                    sw.Stop();

                    Console.WriteLine($"Encryption: {sw.ElapsedMilliseconds} ms.");

                    sw.Restart();
                    var output = rsa.Decrypt(e, false);
                    sw.Stop();
                    Console.WriteLine($"Decryption (advanced): {sw.ElapsedMilliseconds} ms.");


                    sw.Restart();
                    rsa.DecryptDirect = true;
                    var output2 = rsa.Decrypt(e, false);
                    sw.Stop();
                    Console.WriteLine($"Decryption (direct): {sw.ElapsedMilliseconds} ms.");


                    Console.WriteLine($"Expected: {Encoding.UTF8.GetString(input)}\nActual (advanced): {Encoding.UTF8.GetString(output)}\nActual (direct): {Encoding.UTF8.GetString(output2)}");
                }
            }            
        }
    }
}
