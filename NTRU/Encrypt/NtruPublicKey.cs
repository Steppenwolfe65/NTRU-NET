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
using NTRU.Exceptions;
using NTRU.Polynomial;
using NTRU.Encode;
using VTDev.Libraries.CEXEngine.Crypto.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace NTRU.Encrypt
{
    /// <summary>
    /// A NtruEncrypt public key is essentially a polynomial named <c>h</c>.
    /// </summary>
    public sealed class NtruPublicKey : IDisposable
    {
        #region Private Fields
        private bool _isDisposed = false;
        #endregion

        #region Public Fields
        /// <summary>
        /// The number of coefficients in the polynomial <c>H</c>
        /// </summary>
        public int N;
        /// <summary>
        /// The Q modulus
        /// </summary>
        public int Q;
        /// <summary>
        /// The polynomial <c>H</c> which determines the key
        /// </summary>
        public IntegerPolynomial H;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a new public key from a polynomial
        /// </summary>
        /// 
        /// <param name="H">The polynomial <c>H</c> which determines the key</param>
        /// <param name="N">The number of coefficients in the polynomial <c>H</c></param>
        /// <param name="Q">The "big" NtruEncrypt modulus</param>
        public NtruPublicKey(IntegerPolynomial H, int N, int Q)
        {
            this.H = H;
            this.N = N;
            this.Q = Q;
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Key">The encoded key array</param>
        public NtruPublicKey(byte[] Key) :
            this(new MemoryStream(Key))
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NtruPublicKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        public NtruPublicKey(MemoryStream KeyStream)
        {
            try
            {
                N = IntUtils.ReadShort(KeyStream);
                Q = IntUtils.ReadShort(KeyStream);
                H = IntegerPolynomial.FromBinary(KeyStream, N, Q);
            }
            catch (IOException e)
            {
                throw new NtruException(e.Message);
            }
        }
        /// <summary>
        /// Converts the key to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key</returns>
        public byte[] GetEncoded()
        {
            return ArrayExtensions.Concat(ArrayEncoder.ToByteArray(N), ArrayEncoder.ToByteArray(Q), H.ToBinary(Q));
        }

        /// <summary>
        /// Writes the key to an output stream
        /// </summary>
        /// 
        /// <param name="OutputStream">An output stream</param>
        public void WriteTo(MemoryStream OutputStream)
        {
            byte[] buffer = GetEncoded();
            OutputStream.Write(buffer, 0, buffer.Length);
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
            result = prime * result + ((H == null) ? 0 : H.GetHashCode());
            result = prime * result + Q;

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

            NtruPublicKey other = (NtruPublicKey)Obj;
            if (N != other.N)
                return false;

            if (H == null)
            {
                if (other.H != null)
                    return false;
            }
            else if (!H.Equals(other.H))
            {
                return false;
            }
            if (Q != other.Q)
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

                    if (this.H != null)
                        this.H.Clear();
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}