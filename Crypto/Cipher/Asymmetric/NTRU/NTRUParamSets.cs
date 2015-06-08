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
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU
{
    /// <summary>
    /// A set of pre-defined EES encryption parameter sets 
    /// based on <see href="https://github.com/tbuktu/ntru/blob/master/src/main/java/net/sf/ntru/encrypt/EncryptionParameters.java">EncryptionParameters.java</see>.
    /// <para>Note: Sets starting with 'A' (ex. A2011439), are the recommended sets from the original author. Sets pre-fixed with 'F' (ex. FE1087EP2) are the fast polynomial versions. 
    /// Sets prefixed with 'Z' (ex. ZCX1931) are experimental!; they use larger N, df, and dm values, and a 1024 bit digest for the IGF and mask.</para>
    /// </summary>
    public static class NTRUParamSets
    {
        #region Enums
        /// <summary>
        /// EES set id's for common parameter values
        /// </summary>
        public enum NTRUParamNames : int
        {
            /// <summary>
            /// Just an experiment, use at your own risk!
            /// <para>n:1931, q:2048, df:380, skien1024</para>
            /// </summary>
            ZCX1931,
            /// <summary>
            /// Just an experiment, use at your own risk!
            /// <para>n:1861, q:2048, df:290, skien1024</para>
            /// </summary>
            ZCX1861,
            /// <summary>
            /// A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for key size.
            /// </summary>
            E1087EP2,
            /// <summary>
            /// A conservative (in terms of security) parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed.
            /// </summary>
            E1171EP1,
            /// <summary>
            /// A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for encryption/decryption speed.
            /// </summary>
            E1499EP1, 
            /// <summary>
            /// A parameter set that gives 256 bits of security and uses simple ternary polynomials.
            /// </summary>
            A2011439,
            /// <summary>
            /// Like <c>APR2011_743</c>, this parameter set gives 256 bits of security but uses product-form polynomials and <c>f=1+pF</c>. 
            /// </summary>
            A2011743,
            /// <summary>
            /// A product-form version of <c>EES1087EP2</c>
            /// </summary>
            FE1087EP2,
            /// <summary>
            /// A product-form version of <c>EES1171EP1</c>
            /// </summary>
            FE1171EP1,
            /// <summary>
            /// A product-form version of <c>EES1499EP1</c>
            /// </summary>
            FE1499EP1,
            /// <summary>
            /// Like <c>APR2011_439</c>, this parameter set gives 128 bits of security but uses product-form polynomials and <c>f=1+pF</c>.
            /// </summary>
            FA2011439,
            /// <summary>
            /// Like <c>APR2011_743</c>, this parameter set gives 256 bits of security but uses product-form polynomials and <c>f=1+pF</c>. 
            /// </summary>
            FA2011743,
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Retrieve a parameter set by its identity code
        /// </summary>
        /// 
        /// <param name="OId">The 3 byte parameter set identity code</param>
        /// <param name="UseProduct">Use the product form parameters</param>
        /// 
        /// <returns>A parameter set</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if an invalid or unknown OId is used.</exception>
        public static NTRUParameters FromId(byte[] OId, bool UseProduct = true)
        {
            if (OId == null)
                throw new NTRUException("OId can not be null!");
            if (OId.Length != 3)
                throw new NTRUException("OId must be 3 bytes in length!");
            if (OId[0] != 0)
                throw new NTRUException("OId is not a valid NTRU parameter id!");

            if (UseProduct)
            {
                if (OId[2] == 3)
                    return (NTRUParameters)EES1087EP2FAST.Clone();
                else if (OId[2] == 4)
                    return (NTRUParameters)EES1171EP1FAST.Clone();
                else if (OId[2] == 5)
                    return (NTRUParameters)EES1499EP1FAST.Clone();
                else if (OId[2] == 101)
                    return (NTRUParameters)APR2011439FAST.Clone();
                else if (OId[2] == 105)
                    return (NTRUParameters)APR2011743FAST.Clone();
            }
            else
            {
                if (OId[2] == 3)
                    return (NTRUParameters)EES1087EP2.Clone();
                else if (OId[2] == 4)
                    return (NTRUParameters)EES1171EP1.Clone();
                else if (OId[2] == 5)
                    return (NTRUParameters)EES1499EP1.Clone();
                else if (OId[2] == 101)
                    return (NTRUParameters)APR2011439.Clone();
                else if (OId[2] == 105)
                    return (NTRUParameters)APR2011743.Clone();
                else if (OId[2] == 7)
                    return (NTRUParameters)ZCX1861SK1024.Clone();
                else if (OId[2] == 8)
                    return (NTRUParameters)ZCX1931SK1024.Clone();
            }

            throw new NTRUException("OId does not identify a valid param set!");
        }

        /// <summary>
        /// Retrieve a parameter set by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if an invalid or unknown OId is used.</exception>
        public static NTRUParameters FromName(NTRUParamNames Name)
        {
            switch (Name)
            {
                case NTRUParamNames.A2011439:
                    return (NTRUParameters)APR2011439.Clone();
                case NTRUParamNames.A2011743:
                    return (NTRUParameters)APR2011743.Clone();
                case NTRUParamNames.E1087EP2:
                    return (NTRUParameters)EES1087EP2.Clone();
                case NTRUParamNames.E1171EP1:
                    return (NTRUParameters)EES1171EP1.Clone();
                case NTRUParamNames.E1499EP1:
                    return (NTRUParameters)EES1499EP1.Clone();
                case NTRUParamNames.FA2011439:
                    return (NTRUParameters)APR2011439FAST.Clone();
                case NTRUParamNames.FA2011743:
                    return (NTRUParameters)APR2011743FAST.Clone();
                case NTRUParamNames.FE1087EP2:
                    return (NTRUParameters)EES1087EP2FAST.Clone();
                case NTRUParamNames.FE1171EP1:
                    return (NTRUParameters)EES1171EP1FAST.Clone();
                case NTRUParamNames.FE1499EP1:
                    return (NTRUParameters)EES1499EP1FAST.Clone();
                case NTRUParamNames.ZCX1861:
                    return (NTRUParameters)ZCX1861SK1024.Clone();
                case NTRUParamNames.ZCX1931:
                    return (NTRUParameters)ZCX1931SK1024.Clone();
                default:
                    return (NTRUParameters)APR2011743FAST.Clone();
            }
        }
        #endregion

        #region Parameter Sets
        // Note: max message size is calculation of N and Db; (N*3/2/8 - Length-Db/8). Max bytes: EES1087EP2:170, EES1171EP1:186, EES1499EP1:248, APR2011439:65, APR2011743:106
        /// <summary>
        /// Just an experiment, do not use!
        /// <para>n:1931, q:2048, df:380, skien1024</para>
        /// </summary>
        public static readonly NTRUParameters ZCX1931SK1024 = new NTRUParameters(1931, 2048, 380, 380, 0, 1024, 20, 30, 11, true, new byte[] { 0, 8, 8 }, true, false, Digests.Skein1024);
        /// <summary>
        /// Just an experiment, do not use!
        /// <para>n:1861, q:2048, df:290, skien1024</para>
        /// </summary>
        public static readonly NTRUParameters ZCX1861SK1024 = new NTRUParameters(1861, 2048, 290, 290, 0, 1024, 14, 22, 10, true, new byte[] { 0, 7, 7 }, true, false, Digests.Skein1024);
        /// <summary>
        /// A conservative parameter set that gives 256 bits of security and is optimized for key size.
        /// </summary>
        public static readonly NTRUParameters EES1087EP2 = new NTRUParameters(1087, 2048, 120, 120, 0, 256, 13, 25, 14, true, new byte[] { 0, 6, 3 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1087EP2</c>
        /// </summary>
        public static readonly NTRUParameters EES1087EP2FAST = new NTRUParameters(1087, 2048, 8, 8, 11, 120, 0, 256, 13, 25, 14, true, new byte[] { 0, 6, 3 }, true, true, Digests.SHA512);
        /// <summary>
        /// A conservative parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed.
        /// </summary>
        public static readonly NTRUParameters EES1171EP1 = new NTRUParameters(1171, 2048, 106, 106, 0, 256, 13, 20, 15, true, new byte[] { 0, 6, 4 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1171EP1</c>
        /// </summary>
        public static readonly NTRUParameters EES1171EP1FAST = new NTRUParameters(1171, 2048, 8, 7, 11, 106, 0, 256, 13, 20, 15, true, new byte[] { 0, 6, 4 }, true, true, Digests.SHA512);
        /// <summary>
        /// A conservative parameter set that gives 256 bits of security and is optimized for encryption/decryption speed.
        /// </summary>
        public static readonly NTRUParameters EES1499EP1 = new NTRUParameters(1499, 2048, 79, 79, 0, 256, 13, 17, 19, true, new byte[] { 0, 6, 5 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1499EP1</c>
        /// </summary>
        public static readonly NTRUParameters EES1499EP1FAST = new NTRUParameters(1499, 2048, 7, 6, 11, 79, 0, 256, 13, 17, 19, true, new byte[] { 0, 6, 5 }, true, true, Digests.SHA512);
        /// <summary>
        /// A parameter set that gives 128 bits of security and uses simple ternary polynomials.
        /// </summary>
        public static readonly NTRUParameters APR2011439 = new NTRUParameters(439, 2048, 146, 130, 126, 128, 12, 32, 9, true, new byte[] { 0, 7, 101 }, true, false, Digests.SHA256);
        /// <summary>
        /// Like <c>APR2011_439</c>, this parameter set gives 128 bits of security but uses product-form polynomials and <c>f=1+pF</c>.
        /// </summary>
        public static readonly NTRUParameters APR2011439FAST = new NTRUParameters(439, 2048, 9, 8, 5, 130, 126, 128, 12, 32, 9, true, new byte[] { 0, 7, 101 }, true, true, Digests.SHA256);
        /// <summary>
        /// A parameter set that gives 256 bits of security and uses simple ternary polynomials.
        /// </summary>
        public static readonly NTRUParameters APR2011743 = new NTRUParameters(743, 2048, 248, 220, 60, 256, 12, 27, 14, true, new byte[] { 0, 7, 105 }, false, false, Digests.SHA512);
        /// <summary>
        /// Like <c>APR2011_743</c>, this parameter set gives 256 bits of security but uses product-form polynomials and <c>f=1+pF</c>. 
        /// </summary>
        public static readonly NTRUParameters APR2011743FAST = new NTRUParameters(743, 2048, 11, 11, 15, 220, 60, 256, 12, 27, 14, true, new byte[] { 0, 7, 105 }, false, true, Digests.SHA512);
        #endregion
    }
}