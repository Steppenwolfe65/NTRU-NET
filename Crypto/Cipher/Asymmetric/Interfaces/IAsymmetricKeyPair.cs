#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// Asymmetric key pair interface
    /// </summary>
    public interface IAsymmetricKeyPair : ICloneable, IDisposable
    {
        /// <summary>
        /// The Public key
        /// </summary>
        IAsymmetricKey PublicKey { get; }
        /// <summary>
        /// The Private Key
        /// </summary>
        IAsymmetricKey PrivateKey { get; }
    }
}
