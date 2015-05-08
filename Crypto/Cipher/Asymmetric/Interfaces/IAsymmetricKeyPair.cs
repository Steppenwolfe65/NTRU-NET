namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// Asymmetric key pair interface
    /// </summary>
    public interface IAsymmetricKeyPair
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
