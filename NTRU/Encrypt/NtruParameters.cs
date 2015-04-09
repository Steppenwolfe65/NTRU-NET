#region License Information
// NTRU Encrypt in C# (NTRUSharp)
// Copyright (C) 2015 John Underhill
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
//
// Based on the java project NTRUEncrypt by Tim Buktu: <https://github.com/tbuktu/ntru> and the C version
// <https://github.com/NTRUOpenSourceProject/ntru-crypto> NTRUOpenSourceProject/ntru-crypto.
// NTRU is owned and patented by Security Innovations: <https://www.securityinnovation.com/products/encryption-libraries/ntru-crypto/>,
// authors and originators include; Jeffrey Hoffstein, Jill Pipher, and Joseph H. Silverman.
// 
// Implementation Details:
// An implementation of NTRU Encrypt in C#.
// Written by John Underhill, April 09, 2015
// contact: develop@vtdev.com
#endregion

#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace NTRU.Encrypt
{
    #region Enums
    /// <summary>
    /// TernaryPolynomialType enumeration
    /// </summary>
    public enum TernaryPolynomialType
    {
        /// <summary>
        /// Use Ternary type key
        /// </summary>
        SIMPLE,
        /// <summary>
        /// Use Product form type key
        /// </summary>
        PRODUCT
    };
    #endregion

    /// <summary>
    /// A set of pre-defined EES encryption parameter sets 
    /// based on <see href="https://github.com/tbuktu/ntru/blob/master/src/main/java/net/sf/ntru/encrypt/EncryptionParameters.java">EncryptionParameters.java </see>.
    /// </summary>
    public sealed class DefinedParameters
    {
        /*public enum Parameters : int
        {
            [Description("")]
            EES1087EP2 = 0,
            [Description("")]
            EES1087EP2FAST,
            [Description("")]
            EES1171EP1,
            [Description("")]
            EES1171EP1FAST,
            [Description("")]
            EES1499EP1,
            [Description("")]
            EES1499EP1FAST,
            [Description("")]
            APR2011439,
            [Description("")]
            APR2011439FAST,
            [Description("")]
            APR2011743,
            [Description("")]
            APR2011743FAST
        }*/

        private DefinedParameters() { }

        // Note: max message size is calculation of N and Db; (N*3/2/8 - Length-Db/8). Max bytes: EES1087EP2:170, EES1171EP1:186, EES1499EP1:248, APR2011439:65, APR2011743:106

        /// <summary>
        /// A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for key size.
        /// </summary>
        public static NtruParameters EES1087EP2 = new NtruParameters(1087, 2048, 120, 120, 0, 256, 13, 25, 14, true, new byte[] { 0, 6, 3 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1087EP2</c> 
        /// </summary>
        public static NtruParameters EES1087EP2FAST = new NtruParameters(1087, 2048, 8, 8, 11, 120, 0, 256, 13, 25, 14, true, new byte[] { 0, 6, 3 }, true, true, Digests.SHA512);
        /// <summary>
        /// A conservative (in terms of security) parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed.
        /// </summary>
        public static NtruParameters EES1171EP1 = new NtruParameters(1171, 2048, 106, 106, 0, 256, 13, 20, 15, true, new byte[] { 0, 6, 4 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1171EP1</c>
        /// </summary>
        public static NtruParameters EES1171EP1FAST = new NtruParameters(1171, 2048, 8, 7, 11, 106, 0, 256, 13, 20, 15, true, new byte[] { 0, 6, 4 }, true, true, Digests.SHA512);
        /// <summary>
        /// A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for encryption/decryption speed.
        /// </summary>
        public static NtruParameters EES1499EP1 = new NtruParameters(1499, 2048, 79, 79, 0, 256, 13, 17, 19, true, new byte[] { 0, 6, 5 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1499EP1</c>
        /// </summary>
        public static NtruParameters EES1499EP1FAST = new NtruParameters(1499, 2048, 7, 6, 11, 79, 0, 256, 13, 17, 19, true, new byte[] { 0, 6, 5 }, true, true, Digests.SHA512);
        /// <summary>
        /// A parameter set that gives 128 bits of security and uses simple ternary polynomials.
        /// </summary>
        public static NtruParameters APR2011439 = new NtruParameters(439, 2048, 146, 130, 126, 128, 12, 32, 9, true, new byte[] { 0, 7, 101 }, true, false, Digests.SHA256);
        /// <summary>
        /// Like <c>APR2011_439</c>, this parameter set gives 128 bits of security but uses product-form polynomials and <c>f=1+pF</c>.
        /// </summary>
        public static NtruParameters APR2011439FAST = new NtruParameters(439, 2048, 9, 8, 5, 130, 126, 128, 12, 32, 9, true, new byte[] { 0, 7, 101 }, true, true, Digests.SHA256);
        /// <summary>
        /// A parameter set that gives 256 bits of security and uses simple ternary polynomials.
        /// </summary>
        public static NtruParameters APR2011743 = new NtruParameters(743, 2048, 248, 220, 60, 256, 12, 27, 14, true, new byte[] { 0, 7, 105 }, false, false, Digests.SHA512);
        /// <summary>
        /// Like <c>APR2011_743</c>, this parameter set gives 256 bits of security but uses product-form polynomials and <c>f=1+pF</c>. 
        /// </summary>
        public static NtruParameters APR2011743FAST = new NtruParameters(743, 2048, 11, 11, 15, 220, 60, 256, 12, 27, 14, true, new byte[] { 0, 7, 105 }, false, true, Digests.SHA512);
    }

    /// <summary>
    /// Creates, reads and writes parameter settings for NtruEncrypt.
    /// <para>Predefined parameter sets are available and new ones can be created as well.
    /// These predefined settings are accessable through the <see cref="DefinedParameters"/> class</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (NtruParameters np = new NtruParameters(1087, 2048, 120, 120, 0, 256, 13, 25, 14, true, new byte[] { 0, 6, 3 }, true, false, Digests.SHA512))
    ///    np.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.0.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prngs">VTDev.Libraries.CEXEngine.Crypto.Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>NTRU Parameter Description:</h4></description>
    /// <list type="table">
    /// <item><description>N - Degree Parameter. A positive integer. The associated NTRU lattice has dimension 2N.</description></item>
    /// <item><description>q - Large Modulus. A positive integer. The associated NTRU lattice is a convolution modular lattice of modulus q.</description></item>
    /// <item><description>p - Small Modulus. An integer or a polynomial.</description></item>
    /// <item><description>Df, Dg - Private Key Spaces. Sets of small polynomials from which the private keys are selected.</description></item>
    /// <item><description>Dm - Plaintext Space. Set of polynomials that represent encryptable messages.</description></item>
    /// <item><description>Dr - Blinding Value Space. Set of polynomials from which the temporary blinding value used during encryption is selected.</description></item>
    /// <item><description>Center - Centering Method. A means of performing mod q reduction on decryption.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NTRU: A Ring Based Public Key Crypto System<cite>NTRU Crypto</cite>.</description></item>
    /// <item><description>Optimizations for NTRU<cite>NTRU Optimizations</cite>.</description></item>
    /// <item><description>Adaptive Key Recovery Attacks on NTRU-based Somewhat Homomorphic Encryption Schemes<cite>NTRU Adaptive</cite>.</description></item>
    /// <item><description>Efficient Embedded Security Standards (EESS)<cite>NTRU EESS</cite>.</description></item>
    /// <item><description>Practical lattice-based cryptography: NTRUEncrypt and NTRUSign<cite>NTRU Practical</cite>.</description></item>
    /// <item><description>NTRU Cryptosystems Technical Report<cite>NTRU Technical</cite>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the excellent java project NTRU Encrypt by Tim Buktu: <see href="https://github.com/tbuktu/ntru/description">Release 1.2</see>, and
    /// the NTRUOpenSourceProject/ntru-crypto project provided by Security Innovation, Inc <see href="https://github.com/NTRUOpenSourceProject/ntru-crypto">NTRU Encrypt</see>.</description></item>
    /// </list> 
    /// </remarks>
    public class NtruParameters : ICloneable, IDisposable
    {
        #region Fields
        /// <summary>
        /// The ring dimension; the number of polynomial coefficients
        /// </summary>
        public int N;
        /// <summary>
        /// The big q Modulus
        /// </summary>
        public int Q;
        /// <summary>
        /// The number of bits in candidate for deriving an index in IGF-2
        /// </summary>
        public int CBits;
        /// <summary>
        /// Number of random bits to prepend to the message; should be a multiple of 8
        /// </summary>
        public int Db;
        /// <summary>
        /// Number of ones in the private polynomial <c>f</c>
        /// </summary>
        public int DF;
        /// <summary>
        /// Number of ones in the private polynomial <c>f1</c>; Product form of Df
        /// </summary>
        public int DF1;
        /// <summary>
        /// Number of ones in the private polynomial <c>f2</c>; Product form of Df
        /// </summary>
        public int DF2;
        /// <summary>
        /// Number of ones in the private polynomial <c>f3</c>; Product form of Df
        /// </summary>
        public int DF3;
        /// <summary>
        /// Minimum acceptable number of -1's, 0's, and 1's in the polynomial <c>m</c> in the last encryption step
        /// </summary>
        public int Dm0;
        /// <summary>
        /// Blinding Value Space
        /// </summary>
        public int DR;
        /// <summary>
        /// Blinding Value Space <c>dr1</c>; Product form of Dr
        /// </summary>
        public int DR1;
        /// <summary>
        /// Blinding Value Space <c>dr2</c>; Product form of Dr
        /// </summary>
        public int DR2;
        /// <summary>
        /// Blinding Value Space <c>dr3</c>; Product form of Dr
        /// </summary>
        public int DR3;
        /// <summary>
        /// Whether <c>F=1+p*F</c> for a ternary <c>F</c> (true) or <c>F</c> is ternary (false)
        /// </summary>
        public bool FastFp;
        /// <summary>
        /// Whether to hash the seed in the MGF first (true), or use the seed directly (false)
        /// </summary>
        public bool HashSeed;
        /// <summary>
        /// Maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.
        /// </summary>
        public int MaxM1;
        /// <summary>
        /// The maximum length a plaintext message can be with this parameter set
        /// </summary>
        public int MaxMsgLenBytes;
        /// <summary>
        /// The Message Digest engine to use; default is SHA512
        /// </summary>
        public Digests MessageDigest;
        /// <summary>
        /// Minimum number of hash calls for the IGF to make
        /// </summary>
        public int MinIGFHashCalls;
        /// <summary>
        /// Minimum number of calls to generate the masking polynomial
        /// </summary>
        public int MinMGFHashCalls;
        /// <summary>
        /// Three bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] Oid;
        /// <summary>
        /// The polynomial type
        /// </summary>
        public TernaryPolynomialType PolyType;
        /// <summary>
        /// The pseudo random generator engine to use; default is CSPRng
        /// </summary>
        public Prngs RandomEngine;
        /// <summary>
        /// Whether to treat ternary polynomials as sparsely populated; SparseTernaryPolynomial vs DenseTernaryPolynomialinternal
        /// </summary>
        public bool Sparse;

        internal int BufferLenBits;
        private int BufferLenTrits;
        internal int Dg;
        private int Length;
        internal int PkLen;
        private bool _isDisposed = false;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a parameter set that uses ternary private keys (i.e. <c>PolyType=SIMPLE</c>)
        /// </summary>
        /// 
        /// <param name="N">The ring dimension; the number of polynomial coefficients</param>
        /// <param name="Q">The big Q Modulus</param>
        /// <param name="Df">Number of ones in the private polynomial <c>f</c></param>
        /// <param name="Dm0">Minimum acceptable number of -1's, 0's, and 1's in the polynomial <c>m</c> in the last encryption step</param>
        /// <param name="MaxM1">Maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.</param>
        /// <param name="Db">Number of random bits to prepend to the message; should be a multiple of 8</param>
        /// <param name="CBits">The number of bits in candidate for deriving an index in IGF-2</param>
        /// <param name="MinIGFHashCalls">Minimum number of hash calls for the IGF to make</param>
        /// <param name="MinMGFHashCalls">Minimum number of calls to generate the masking polynomial</param>
        /// <param name="HashSeed">Whether to hash the seed in the MGF first (true), or use the seed directly (false)</param>
        /// <param name="Oid">Three bytes that uniquely identify the parameter set</param>
        /// <param name="Sparse">Whether to treat ternary polynomials as sparsely populated; SparseTernaryPolynomial vs DenseTernaryPolynomial</param>
        /// <param name="FastFp">Whether <c>f=1+p*F</c> for a ternary <c>F</c> (true) or <c>f</c> is ternary (false)</param>
        /// <param name="Digest">The Message Digest engine to use; default is SHA512</param>
        /// <param name="Random">The pseudo random generator engine to use; default is CSPRng</param>
        public NtruParameters(int N, int Q, int Df, int Dm0, int MaxM1, int Db, int CBits, int MinIGFHashCalls, int MinMGFHashCalls, 
            bool HashSeed, byte[] Oid, bool Sparse, bool FastFp, Digests Digest = Digests.SHA512, Prngs Random = Prngs.CSPRng)
        {
            this.N = N;
            this.Q = Q;
            this.DF = Df;
            this.Db = Db;
            this.Dm0 = Dm0;
            this.MaxM1 = MaxM1;
            this.CBits = CBits;
            this.MinIGFHashCalls = MinIGFHashCalls;
            this.MinMGFHashCalls = MinMGFHashCalls;
            this.HashSeed = HashSeed;
            this.Oid = Oid;
            this.Sparse = Sparse;
            this.FastFp = FastFp;
            this.PolyType = TernaryPolynomialType.SIMPLE;
            this.MessageDigest = Digest;
            this.RandomEngine = Random;

            Initialize();
        }

        /// <summary>
        /// Constructs a parameter set that uses product-form private keys (i.e. <c>PolyType=PRODUCT</c>).
        /// </summary>
        /// 
        /// <param name="N">N number of polynomial coefficients</param>
        /// <param name="Q">The big Q Modulus</param>
        /// <param name="Df1">Number of ones in the private polynomial <c>f1</c></param>
        /// <param name="Df2">Number of ones in the private polynomial <c>f2</c></param>
        /// <param name="Df3">Number of ones in the private polynomial <c>f3</c></param>
        /// <param name="Dm0">Minimum acceptable number of -1's, 0's, and 1's in the polynomial <c>m'</c> in the last encryption step</param>
        /// <param name="MaxM1">Maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.</param>
        /// <param name="Db">Number of random bits to prepend to the message; should be a multiple of 8</param>
        /// <param name="CBits">The number of bits in candidate for deriving an index in IGF-2</param>
        /// <param name="MinIGFHashCalls">Minimum number of hash calls for the IGF to make</param>
        /// <param name="MinMGFHashCalls">Minimum number of calls to generate the masking polynomial</param>
        /// <param name="HashSeed">Whether to hash the seed in the MGF first (true) or use the seed directly (false)</param>
        /// <param name="Oid">Three bytes that uniquely identify the parameter set</param>
        /// <param name="Sparse">Whether to treat ternary polynomials as sparsely populated SparseTernaryPolynomial vs DenseTernaryPolynomial</param>
        /// <param name="FastFp">Whether <c>F=1+p*F</c> for a ternary <c>F</c> (true) or <c>F</c> is ternary (false)</param>
        /// <param name="Digest">The Message Digest engine to use; default is SHA512</param>
        /// <param name="Random">The pseudo random generator engine to use; default is CSPRng</param>
        public NtruParameters(int N, int Q, int Df1, int Df2, int Df3, int Dm0, int MaxM1, int Db, int CBits, int MinIGFHashCalls, int MinMGFHashCalls, 
            bool HashSeed, byte[] Oid, bool Sparse, bool FastFp, Digests Digest = Digests.SHA512, Prngs Random = Prngs.CSPRng)
        {
            this.N = N;
            this.Q = Q;
            this.DF1 = Df1;
            this.DF2 = Df2;
            this.DF3 = Df3;
            this.Db = Db;
            this.Dm0 = Dm0;
            this.MaxM1 = MaxM1;
            this.CBits = CBits;
            this.MinIGFHashCalls = MinIGFHashCalls;
            this.MinMGFHashCalls = MinMGFHashCalls;
            this.HashSeed = HashSeed;
            this.Oid = Oid;
            this.Sparse = Sparse;
            this.FastFp = FastFp;
            this.PolyType = TernaryPolynomialType.PRODUCT;
            this.MessageDigest = Digest;
            this.RandomEngine = Random;

            Initialize();
        }

        /// <summary>
        /// Reads a parameter set from an input stream
        /// </summary>
        /// 
        /// <param name="ParamStream">Stream containing a parameter set</param>
        public NtruParameters(MemoryStream ParamStream)
        {
            BinaryReader reader = new BinaryReader(ParamStream);

            N = reader.ReadInt32();
            Q = reader.ReadInt32();
            DF = reader.ReadInt32();
            DF1 = reader.ReadInt32();
            DF2 = reader.ReadInt32();
            DF3 = reader.ReadInt32();
            Db = reader.ReadInt32();
            Dm0 = reader.ReadInt32();
            MaxM1 = reader.ReadInt32();
            CBits = reader.ReadInt32();
            MinIGFHashCalls = reader.ReadInt32();
            MinMGFHashCalls = reader.ReadInt32();
            HashSeed = reader.ReadBoolean();
            Oid = new byte[3];
            reader.Read(Oid, 0, Oid.Length);
            Sparse = reader.ReadBoolean();
            FastFp = reader.ReadBoolean();
            PolyType = (TernaryPolynomialType)reader.ReadInt32();
            MessageDigest = (Digests)reader.ReadInt32();
            RandomEngine = (Prngs)reader.ReadInt32();

            Initialize();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NtruParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a copy of this EncryptionParameters instance
        /// </summary>
        /// 
        /// <returns>EncryptionParameters copy</returns>
        public object Clone()
        {
            if (PolyType == TernaryPolynomialType.SIMPLE)
                return new NtruParameters(N, Q, DF, Dm0, MaxM1, Db, CBits, MinIGFHashCalls, MinMGFHashCalls, HashSeed, Oid, Sparse, FastFp, MessageDigest);
            else
                return new NtruParameters(N, Q, DF1, DF2, DF3, Dm0, MaxM1, Db, CBits, MinIGFHashCalls, MinMGFHashCalls, HashSeed, Oid, Sparse, FastFp, MessageDigest);
        }

        /// <summary>
        /// Returns the maximum length a plaintext message can be with this parameter set
        /// </summary>
        /// 
        /// <returns>The maximum length in bytes</returns>
        public int GetMaxMessageLength()
        {
            return MaxMsgLenBytes;
        }

        /// <summary>
        /// Returns the length of a message after encryption with this parameter set
        /// <para>The length does not depend on the input size.</para>
        /// </summary>
        /// 
        /// <returns>The length in bytes</returns>
        public int GetOutputLength()
        {
            // ceil(log q)
            int logq = 32 - IntUtils.NumberOfLeadingZeros(Q - 1); 
            return (N * logq + 7) / 8;
        }

        /// <summary>
        /// Writes the parameter set to an output stream
        /// </summary>
        /// 
        /// <param name="OutputStream">Output Stream</param>
        public void WriteTo(MemoryStream OutputStream)
        {
            BinaryWriter writer = new BinaryWriter(OutputStream); 

            writer.Write(N);
            writer.Write(Q);
            writer.Write(DF);
            writer.Write(DF1);
            writer.Write(DF2);
            writer.Write(DF3);
            writer.Write(Db);
            writer.Write(Dm0);
            writer.Write(MaxM1);
            writer.Write(CBits);
            writer.Write(MinIGFHashCalls);
            writer.Write(MinMGFHashCalls);
            writer.Write(HashSeed);
            writer.Write(Oid);
            writer.Write(Sparse);
            writer.Write(FastFp);
            writer.Write((int)PolyType);
            writer.Write((int)MessageDigest);
            writer.Write((int)RandomEngine);
        }
        #endregion

        #region Private Methods
        private void Initialize()
        {
            DR = DF;
            DR1 = DF1;
            DR2 = DF2;
            DR3 = DF3;
            Dg = N / 3;
            Length = 1;   // ceil(log2(maxMsgLenBytes))

            if (MaxM1 > 0)
                MaxMsgLenBytes = (N - 1) * 3 / 2 / 8 - Length - Db / 8;   // only N-1 coeffs b/c the constant coeff is not used
            else
                MaxMsgLenBytes = N * 3 / 2 / 8 - Length - Db / 8;

            BufferLenBits = (N * 3 / 2 + 7) / 8 * 8 + 1;
            BufferLenTrits = N - 1;
            PkLen = Db;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;

            result = prime * result + N;
            result = prime * result + BufferLenBits;
            result = prime * result + BufferLenTrits;
            result = prime * result + CBits;
            result = prime * result + Db;
            result = prime * result + DF;
            result = prime * result + DF1;
            result = prime * result + DF2;
            result = prime * result + DF3;
            result = prime * result + Dg;
            result = prime * result + Dm0;
            result = prime * result + MaxM1;
            result = prime * result + DR;
            result = prime * result + DR1;
            result = prime * result + DR2;
            result = prime * result + DR3;
            result = prime * result + (FastFp ? 1231 : 1237);
            result = prime * result + MessageDigest.GetHashCode();
            result = prime * result + RandomEngine.GetHashCode();
            result = prime * result + (HashSeed ? 1231 : 1237);
            result = prime * result + Length;
            result = prime * result + MaxMsgLenBytes;
            result = prime * result + MinMGFHashCalls;
            result = prime * result + MinIGFHashCalls;
            result = prime * result + Oid.GetHashCode();
            result = prime * result + PkLen;
            result = prime * result + PolyType.GetHashCode();
            result = prime * result + Q;
            result = prime * result + (Sparse ? 1231 : 1237);

            return result;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;
            if (Obj == null)
                return false;

            NtruParameters other = (NtruParameters)Obj;
            if (N != other.N)
                return false;
            if (BufferLenBits != other.BufferLenBits)
                return false;
            if (BufferLenTrits != other.BufferLenTrits)
                return false;
            if (CBits != other.CBits)
                return false;
            if (Db != other.Db)
                return false;
            if (DF != other.DF)
                return false;
            if (DF1 != other.DF1)
                return false;
            if (DF2 != other.DF2)
                return false;
            if (DF3 != other.DF3)
                return false;
            if (Dg != other.Dg)
                return false;
            if (Dm0 != other.Dm0)
                return false;
            if (MaxM1 != other.MaxM1)
                return false;
            if (DR != other.DR)
                return false;
            if (DR1 != other.DR1)
                return false;
            if (DR2 != other.DR2)
                return false;
            if (DR3 != other.DR3)
                return false;
            if (FastFp != other.FastFp)
                return false;
            if (!MessageDigest.Equals(other.MessageDigest))
                return false;
            if (!RandomEngine.Equals(other.RandomEngine))
                return false;
            if (HashSeed != other.HashSeed)
                return false;
            if (Length != other.Length)
                return false;
            if (MaxMsgLenBytes != other.MaxMsgLenBytes)
                return false;
            if (MinMGFHashCalls != other.MinMGFHashCalls)
                return false;
            if (MinIGFHashCalls != other.MinIGFHashCalls)
                return false;
            if (!Compare.AreEqual(Oid, other.Oid))
                return false;
            if (PkLen != other.PkLen)
                return false;
            if (!PolyType.Equals(other.PolyType))
                return false;
            if (Q != other.Q)
                return false;
            if (Sparse != other.Sparse)
                return false;

            return true;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    this.N = 0;
                    this.Q = 0;
                    this.DF = 0;
                    this.DF1 = 0;
                    this.DF2 = 0;
                    this.DF3 = 0;
                    this.Db = 0;
                    this.Dm0 = 0;
                    this.MaxM1 = 0;
                    this.CBits = 0;
                    this.MinIGFHashCalls = 0;
                    this.MinMGFHashCalls = 0;

                    if (Oid != null)
                    {
                        Array.Clear(Oid, 0, Oid.Length);
                        Oid = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}