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
        static string TestText = "RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest.";

        static void Main(string[] args)
        {
            var hw = Encoding.UTF8.GetBytes(TestText);

            Stopwatch sw = new Stopwatch();

            for (int i = 512; i <= 1024; i += 128)
            {
                Console.WriteLine();
                Console.WriteLine($"*RSA {i}-bits*");
                Console.WriteLine("Type | KeyGen time (ms.) | Encryption time (ms.) | Decryption time (optimized) (ms.) | Decryption time (direct) (ms.)");
                Console.WriteLine("--- | --- | --- | --- | ---");
                using (var rsa = new RSA.RSAProvider(i))
                {
                    sw.Restart();
                    rsa.InitializeParameters();
                    sw.Stop();

                    var len = rsa.GetParameters().Modulus.GetByteCount() - 2 * rsa.HashOutputSize;
                    // Console.WriteLine($"Input length: {len} bytes");

                    Console.Write($"RSA ");

                    Console.Write($"| {sw.ElapsedMilliseconds} ");

                    { 
                        var input = hw.Take(len).ToArray();
                        sw.Restart();
                        var e = rsa.Encrypt(input, false);
                        sw.Stop();

                        Console.Write($"| {sw.ElapsedMilliseconds} ");

                        sw.Restart();
                        var output = rsa.Decrypt(e, false);
                        sw.Stop();
                        Console.Write($"| {sw.ElapsedMilliseconds} ");


                        sw.Restart();
                        rsa.DecryptDirect = true;
                        var output2 = rsa.Decrypt(e, false);
                        sw.Stop();
                        Console.Write($"| {sw.ElapsedMilliseconds} ");

                        //Console.WriteLine($"Expected: {Encoding.UTF8.GetString(input)}\nActual (advanced): {Encoding.UTF8.GetString(output)}\nActual (direct): {Encoding.UTF8.GetString(output2)}");
                    }
                    Console.WriteLine();
                    Console.Write($"RSA-OAEP ");
                    Console.Write($"| = ");
                    {
                        var input = hw.Take(len).ToArray();
                        sw.Restart();
                        var e = rsa.Encrypt(input, true);
                        sw.Stop();
                        Console.Write($"| {sw.ElapsedMilliseconds} ");

                        sw.Restart();
                        var output = rsa.Decrypt(e, true);
                        sw.Stop();
                        Console.Write($"| {sw.ElapsedMilliseconds} ");


                        sw.Restart();
                        rsa.DecryptDirect = true;
                        var output2 = rsa.Decrypt(e, true);
                        sw.Stop();
                        Console.Write($"| {sw.ElapsedMilliseconds} ");


                        //Console.WriteLine($"Expected: {Encoding.UTF8.GetString(input)}\nActual (advanced): {Encoding.UTF8.GetString(output)}\nActual (direct): {Encoding.UTF8.GetString(output2)}");
                    }
                }
            }

            Console.ReadLine();
        }
    }
}
