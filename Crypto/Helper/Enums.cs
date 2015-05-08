namespace VTDev.Libraries.CEXEngine.Crypto
{
    #region Enums
    /// <summary>
    /// Message Digests
    /// </summary>
    public enum Digests : int
    {
        /// <summary>
        /// The Blake digest with a 256 bit return size
        /// </summary>
        Blake256 = 0,
        /// <summary>
        /// The Blake digest with a 512 bit return size
        /// </summary>
        Blake512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 512 bit return size
        /// </summary>
        Keccak256,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 256 bit return size
        /// </summary>
        Keccak512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 1024 bit return size
        /// </summary>
        Keccak1024,
        /// <summary>
        ///The SHA-2 digest with a 256 bit return size
        /// </summary>
        SHA256,
        /// <summary>
        /// The SHA-2 digest with a 512 bit return size
        /// </summary>
        SHA512,
        /// <summary>
        /// The Skein digest with a 256 bit return size
        /// </summary>
        Skein256,
        /// <summary>
        /// The Skein digest with a 512 bit return size
        /// </summary>
        Skein512,
        /// <summary>
        /// The Skein digest with a 1024 bit return size
        /// </summary>
        Skein1024
    }

    /// <summary>
    /// Pseudo Random Generators
    /// </summary>
    public enum Prngs : int
    {
        /// <summary>
        /// A Blum-Blum-Shub random number generator
        /// </summary>
        BBSG = 0,
        /// <summary>
        /// A Cubic Congruential Generator II (CCG) random number generator
        /// </summary>
        CCG,
        /// <summary>
        ///  A Secure PRNG using RNGCryptoServiceProvider
        /// </summary>
        CSPRng,
        /// <summary>
        /// A Modular Exponentiation Generator (MODEXPG) random number generator
        /// </summary>
        MODEXPG,
        /// <summary>
        /// A Quadratic Congruential Generator I (QCG-I) random number generator
        /// </summary>
        QCG1,
        /// <summary>
        /// A Quadratic Congruential Generator II (QCG-II) random number generator
        /// </summary>
        QCG2
    }
    #endregion
}