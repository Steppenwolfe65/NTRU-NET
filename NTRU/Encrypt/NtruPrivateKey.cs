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
    /// A NtruEncrypt private key is essentially a polynomial named <c>f</c>
    /// which takes different forms depending on whether product-form polynomials are used. 
    /// <para>On <c>FastP</c> the inverse of <c>f</c> modulo <c>p</c> is precomputed on initialization.</para>
    /// </summary>
    public sealed class NtruPrivateKey : IDisposable
    {
        #region Private Fields
        private bool _isDisposed = false;
        #endregion

        #region Public Fields
        /// <summary>
        /// The number of polynomial coefficients
        /// </summary>
        public int N;
        /// <summary>
        /// The Q modulus
        /// </summary>
        public int Q;
        /// <summary>
        /// PolyType type of the polynomial <c>T</c>
        /// </summary>
        public TernaryPolynomialType PolyType;
        /// <summary>
        /// The polynomial which determines the key: if <c>FastFp=true</c>, <c>F=1+3T</c>; otherwise, <c>F=T</c>
        /// </summary>
        public IPolynomial T;
        /// <summary>
        /// Fp the inverse of <c>F</c>
        /// </summary>
        public IntegerPolynomial FP;
        #endregion

        #region Private Fields
        private bool _sparse;
        private bool _fastFp;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a new private key from a polynomial
        /// </summary>
        /// 
        /// <param name="T">The polynomial which determines the key: if <c>FastFp=true</c>, <c>f=1+3T</c>; otherwise, <c>f=T</c></param>
        /// <param name="FP">Fp the inverse of <c>f</c></param>
        /// <param name="N">The number of polynomial coefficients</param>
        /// <param name="Q">The big q modulus</param>
        /// <param name="Sparse">Sparse whether the polynomial <c>T</c> is sparsely or densely populated</param>
        /// <param name="FastFp">FastFp whether <c>FP=1</c></param>
        /// <param name="PolyType">PolyType type of the polynomial <c>T</c></param>
        public NtruPrivateKey(IPolynomial T, IntegerPolynomial FP, int N, int Q, bool Sparse, bool FastFp, TernaryPolynomialType PolyType)
        {
            this.T = T;
            this.FP = FP;
            this.N = N;
            this.Q = Q;
            this._sparse = Sparse;
            this._fastFp = FastFp;
            this.PolyType = PolyType;
        }

        /// <summary>
        /// Converts a byte array to a polynomial <c>f</c> and constructs a new private key
        /// </summary>
        /// 
        /// <param name="B">An encoded polynomial</param>
        public NtruPrivateKey(byte[] B) :
            this(new MemoryStream(B))
        {
        }

        /// <summary>
        /// Reads a polynomial <c>f</c> from an input stream and constructs a new private key
        /// </summary>
        /// 
        /// <param name="InputStream">An input stream</param>
        public NtruPrivateKey(MemoryStream InputStream)
        {
            BinaryReader dataStream = new BinaryReader(InputStream);

            try
            {
                // ins.Position = 0; wrong here, ins pos is wrong
                N = IntUtils.ReadShort(InputStream);
                Q = IntUtils.ReadShort(InputStream);
                byte flags = dataStream.ReadByte();
                _sparse = (flags & 1) != 0;
                _fastFp = (flags & 2) != 0;

                PolyType = (flags & 4) == 0 ? 
                    TernaryPolynomialType.SIMPLE : 
                    TernaryPolynomialType.PRODUCT;

                if (PolyType == TernaryPolynomialType.PRODUCT)
                {
                    T = ProductFormPolynomial.FromBinary(InputStream, N);
                }
                else
                {
                    IntegerPolynomial fInt = IntegerPolynomial.FromBinary3Tight(InputStream, N);

                    if (_sparse)
                        T = new SparseTernaryPolynomial(fInt);
                    else
                        T = new DenseTernaryPolynomial(fInt);
                }
            }
            catch (IOException e)
            {
                throw new NtruException(e.Message);
            }

            Initialize();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~NtruPrivateKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Converts the key to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key</returns>
        public byte[] GetEncoded()
        {
            int flags = (_sparse ? 1 : 0) + (_fastFp ? 2 : 0) + (PolyType == TernaryPolynomialType.PRODUCT ? 4 : 0);
            byte[] flagsByte = new byte[] { (byte)flags };
            byte[] tBin;

            if (T.GetType().Equals(typeof(ProductFormPolynomial)))
                tBin = ((ProductFormPolynomial)T).ToBinary();
            else
                tBin = T.ToIntegerPolynomial().ToBinary3Tight();

            return ArrayExtensions.Concat(ArrayEncoder.ToByteArray(N), ArrayEncoder.ToByteArray(Q), flagsByte, tBin);
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

        #region Private Methods
        private void Initialize()
        {
            // Initializes fp from t
            if (_fastFp)
            {
                FP = new IntegerPolynomial(N);
                FP.Coeffs[0] = 1;
            }
            else
            {
                FP = T.ToIntegerPolynomial().InvertF3();
            }
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
            result = prime * result + (_fastFp ? 1231 : 1237);
            result = prime * result + ((FP == null) ? 0 : FP.GetHashCode());
            result = prime * result + PolyType.GetHashCode();
            result = prime * result + Q;
            result = prime * result + (_sparse ? 1231 : 1237);
            result = prime * result + ((T == null) ? 0 : T.GetHashCode());

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

            NtruPrivateKey other = (NtruPrivateKey)obj;
            if (N != other.N)
                return false;
            if (_fastFp != other._fastFp)
                return false;

            if (FP == null)
            {
                if (other.FP != null)
                    return false;
            }
            else if (!FP.Equals(other.FP))
            {
                return false;
            }

            if (PolyType != other.PolyType)
                return false;
            if (Q != other.Q)
                return false;
            if (_sparse != other._sparse)
                return false;

            if (T == null)
            {
                if (other.T != null)
                    return false;
            }
            else if (!T.Equals(other.T))
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
                    this.N = 0;
                    this.Q = 0;
                    this.T.Clear();
                    this.FP.Clear();
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}