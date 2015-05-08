namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces
{
    /// <summary>
    /// The Asymmetric cipher interface
    /// </summary>
    public interface IAsymmetricCipher
    {
        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        int MaxCipherText { get; }

        /// <summary>
        /// Initialize the cipher
        /// </summary>
        /// 
        /// <param name="Encryption">When true cipher is for encryption, if false, decryption</param>
        /// <param name="KeyPair">The public and private key pair</param>
        void Initialize(bool Encryption, IAsymmetricKeyPair KeyPair);

        /// <summary>
        /// Decrypt a cipher text
        /// </summary>
        /// 
        /// <param name="Input">The cipher text</param>
        /// 
        /// <returns>The plain text</returns>
        byte[] Decrypt(byte[] Input);

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        byte[] Encrypt(byte[] Input);
    }
}
