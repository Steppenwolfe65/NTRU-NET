#region Directives
using System;
using Test.Tests.Arith;
using Test.Tests.Encode;
using Test.Tests.Encrypt;
using Test.Tests.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU;
#endregion

namespace Test
{
    /// <summary>
    /// Original NTRUEncrypt paper: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8422&rep=rep1&type=pdf
    /// Follow-up NTRUEncrypt paper: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.64.6834&rep=rep1&type=pdf
    /// Original NTRUSign paper: http://www.math.brown.edu/~jpipher/NTRUSign_RSA.pdf
    /// Follow-up NTRUSign paper: http://grouper.ieee.org/groups/1363/WorkingGroup/presentations/NTRUSignParams-2005-08.pdf
    /// NTRU articles (technical and mathematical): http://www.securityinnovation.com/security-lab/crypto.html
    /// Jeffrey Hoffstein et al: An Introduction to Mathematical Cryptography, Springer-Verlag, ISBN 978-0-387-77993-5 
    /// EESS: http://grouper.ieee.org/groups/1363/lattPK/submissions/EESS1v2.pdf
    /// </summary>
    static class Program
    {
        static void Main(string[] args)
        {
            // header
            Console.WriteLine("**********************************************");
            Console.WriteLine("* NTRU Encrypt in C# (NTRU Sharp)            *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.0                            *");
            Console.WriteLine("* Date:      April 05, 2015                  *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");

            // math
            Console.WriteLine("******TESTING BIGINTEGER MATH FUNCTIONS******");
            RunTest(new BigIntEuclideanTest());
            RunTest(new IntEuclideanTest());
            RunTest(new SchönhageStrassenTest());/**/

            // polynomials
            Console.WriteLine("******TESTING POLYNOMINAL FUNCTIONS******");
            RunTest(new BigDecimalPolynomialTest());
            RunTest(new BigIntPolynomialTest());
            RunTest(new DenseTernaryPolynomialTest());
            RunTest(new IntegerPolynomialTest());
            RunTest(new LongPolynomial2Test());
            RunTest(new LongPolynomial5Test());
            RunTest(new ProductFormPolynomialTest());
            RunTest(new SparseTernaryPolynomialTest());
            Console.WriteLine("");/**/

            // utils
            Console.WriteLine("******TESTING ARRAY ENCODERS******");
            RunTest(new ArrayEncoderTest());
            Console.WriteLine("");/**/

            // encrypt
            Console.WriteLine("******TESTING ENCRYPTION ENGINE******");
            RunTest(new BitStringTest());
            RunTest(new NtruKeyPairTest());
            RunTest(new NtruKeyTest());
            RunTest(new NtruParametersTest());
            RunTest(new IndexGeneratorTest());
            RunTest(new NtruEncryptTest());
            RunTest(new PBPRngTest());
            Console.WriteLine("");/**/

            Console.WriteLine("Completed! Press any key to close..");
            Console.ReadKey();
        }

        private static void Tex()
        {
            NTRUParameters param = NTRUParamSets.CX2100SK1024;
            NTRUEncrypt ntru = new NTRUEncrypt(param);
            NTRUKeyPair kp;
            using (NTRUKeyGenerator kg = new NTRUKeyGenerator(param))
                kp = kg.GenerateKeyPair();

            byte[] plainText = Test.Tests.ByteUtils.GetBytes("text to encrypt");
            ntru.Initialize(true, kp);
            byte[] encrypted = ntru.Encrypt(plainText);
            ntru.Initialize(false, kp);
            byte[] decrypted = ntru.Decrypt(encrypted);
        }

        private static void RunTest(ITest Test)
        {
            try
            {
                Test.Progress -= OnTestProgress;
                Test.Progress += new EventHandler<TestEventArgs>(OnTestProgress);
                Console.WriteLine(Test.Description);
                Console.WriteLine(Test.Test());
                Console.WriteLine();
            }
            catch (Exception Ex)
            {
                Console.WriteLine("An error has occured!");
                Console.WriteLine(Ex.Message);
                Console.WriteLine("");
                Console.WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");
                ConsoleKeyInfo keyInfo = Console.ReadKey();

                if (!keyInfo.Key.Equals(ConsoleKey.Y))
                    Environment.Exit(0);
                else
                    Console.WriteLine();
            }
        }

        private static void OnTestProgress(object sender, TestEventArgs e)
        {
            Console.WriteLine(e.Message);
        }
    }
}
