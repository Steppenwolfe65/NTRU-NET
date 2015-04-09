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
using NTRU.Arithmetic;
using NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace NTRU.Encrypt
{
    /// <summary>
    /// An Ntru Key-Pair container
    /// </summary>
    public sealed class NtruKeyPair : IDisposable
    {
        #region Private Fields
        private bool _isDisposed = false;
        #endregion

        #region Public Fields
        /// <summary>
        /// The Private Key
        /// </summary>
        public NtruPrivateKey PrivateKey;
        /// <summary>
        /// The Public Key
        /// </summary>
        public NtruPublicKey PublicKey;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a new key pair
        /// </summary>
        /// 
        /// <param name="PrivateKey">The Private Key</param>
        /// <param name="PublicKey">The Public key</param>
        public NtruKeyPair(NtruPrivateKey PrivateKey, NtruPublicKey PublicKey)
        {
            this.PrivateKey = PrivateKey;
            this.PublicKey = PublicKey;
        }

        /// <summary>
        /// Constructs a new key pair from a byte array
        /// </summary>
        /// 
        /// <param name="KeyPair">An encoded key pair</param>
        public NtruKeyPair(byte[] KeyPair)
        {
            using (MemoryStream keyStream = new MemoryStream(KeyPair))
            {
                PublicKey = new NtruPublicKey(keyStream);
                PrivateKey = new NtruPrivateKey(keyStream);
            }
        }

        /// <summary>
        /// Constructs a new key pair from an input stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key pair</param>
        public NtruKeyPair(MemoryStream KeyStream)
        {
            PublicKey = new NtruPublicKey(KeyStream);
            PrivateKey = new NtruPrivateKey(KeyStream);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NtruKeyPair()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Returns the private key
        /// </summary>
        /// 
        /// <returns>The private key</returns>
        public NtruPrivateKey GetPrivateKey()
        {
            return PrivateKey;
        }

        /// <summary>
        /// Returns the public key
        /// </summary>
        /// 
        /// <returns>The public key</returns>
        public NtruPublicKey GetPublicKey()
        {
            return PublicKey;
        }

        /// <summary>
        /// Tests if the key pair is valid.
        /// <para>See IEEE 1363.1 section 9.2.4.1.</para>
        /// </summary>
        /// 
        /// <returns>if the key pair is valid, <c>true</c> otherwise false</returns>
        public bool IsValid()
        {
            int N = PrivateKey.N;
            int q = PrivateKey.Q;
            TernaryPolynomialType polyType = PrivateKey.PolyType;

            if (PublicKey.N != N)
                return false;
            if (PublicKey.Q != q)
                return false;

            if (PrivateKey.T.ToIntegerPolynomial().Coeffs.Length != N)
                return false;

            IntegerPolynomial h = PublicKey.H.ToIntegerPolynomial();
            if (h.Coeffs.Length != N)
                return false;
            if (!h.IsReduced(q))
                return false;

            IntegerPolynomial f = PrivateKey.T.ToIntegerPolynomial();
            if (polyType == TernaryPolynomialType.SIMPLE && !f.IsTernary())
                return false;
            // if t is a ProductFormPolynomial, ternarity of f1,f2,f3 doesn't need to be verified
            if (polyType == TernaryPolynomialType.PRODUCT && !(PrivateKey.T.GetType().Equals(typeof(ProductFormPolynomial))))
                return false;

            if (polyType == TernaryPolynomialType.PRODUCT)
            {
                f.Multiply(3);
                f.Coeffs[0] += 1;
                f.ModPositive(q);
            }

            // the key generator pre-multiplies h by 3, so divide by 9 instead of 3
            int inv9 = IntEuclidean.Calculate(9, q).X;   // 9^-1 mod q

            IntegerPolynomial g = f.Multiply(h, q);
            g.Multiply(inv9);
            g.ModCenter(q);

            if (!g.IsTernary())
                return false;

            int dg = N / 3;   // see EncryptionParameters.Initialize()
            if (g.Count(1) != dg)
                return false;
            if (g.Count(-1) != dg - 1)
                return false;

            return true;
        }

        /// <summary>
        /// Converts the key pair to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key pair</returns>
        public byte[] GetEncoded()
        {
            byte[] pubArr = PublicKey.GetEncoded();
            byte[] privArr = PrivateKey.GetEncoded();
            byte[] kpArr = pubArr.CopyOf(pubArr.Length + privArr.Length);
            Array.Copy(privArr, 0, kpArr, pubArr.Length, privArr.Length);

            return kpArr;
        }

        /// <summary>
        /// Writes the key pair to an output stream
        /// </summary>
        /// 
        /// <param name="KeyStream">Output Stream</param>
        public void WriteTo(MemoryStream KeyStream)
        {
            byte[] buffer = GetEncoded();
            KeyStream.Write(buffer, 0, buffer.Length);
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

            result = prime * result + ((PrivateKey == null) ? 0 : PrivateKey.GetHashCode());
            result = prime * result + ((PublicKey == null) ? 0 : PublicKey.GetHashCode());

            return result;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object obj)
        {
            if (this == obj)
                return true;
            if (obj == null)
                return false;

            NtruKeyPair other = (NtruKeyPair)obj;
            if (PrivateKey == null)
            {
                if (other.PrivateKey != null)
                    return false;
            }
            else if (!PrivateKey.Equals(other.PrivateKey))
            {
                return false;
            }
            if (PublicKey == null)
            {
                if (other.PublicKey != null)
                    return false;
            }
            else if (!PublicKey.Equals(other.PublicKey))
            {
                return false;
            }

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
                    if (PrivateKey != null)
                        PrivateKey.Dispose();
                    if (PublicKey != null)
                        PublicKey.Dispose();
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}