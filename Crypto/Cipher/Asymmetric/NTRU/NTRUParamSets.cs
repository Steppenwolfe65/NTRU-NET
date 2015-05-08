namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU
{
    /// <summary>
    /// A set of pre-defined EES encryption parameter sets 
    /// based on <see href="https://github.com/tbuktu/ntru/blob/master/src/main/java/net/sf/ntru/encrypt/EncryptionParameters.java">EncryptionParameters.java</see>.
    /// </summary>
    public static class NTRUParamSets
    {
        // Note: max message size is calculation of N and Db; (N*3/2/8 - Length-Db/8). Max bytes: EES1087EP2:170, EES1171EP1:186, EES1499EP1:248, APR2011439:65, APR2011743:106
        /// <summary>
        /// Just an experiment, do not use!
        /// </summary>
        public static NTRUParameters CX2100SK1024 = new NTRUParameters(2100, 2048, 204, 204, 0, 512, 18, 38, 24, true, new byte[] { 0, 1, 2 }, true, false, Digests.Skein1024);
        /// <summary>
        /// A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for key size.
        /// </summary>
        public static NTRUParameters EES1087EP2 = new NTRUParameters(1087, 2048, 120, 120, 0, 256, 13, 25, 14, true, new byte[] { 0, 6, 3 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1087EP2</c>
        /// </summary>
        public static NTRUParameters EES1087EP2FAST = new NTRUParameters(1087, 2048, 8, 8, 11, 120, 0, 256, 13, 25, 14, true, new byte[] { 0, 6, 3 }, true, true, Digests.SHA512);
        /// <summary>
        /// A conservative (in terms of security) parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed.
        /// </summary>
        public static NTRUParameters EES1171EP1 = new NTRUParameters(1171, 2048, 106, 106, 0, 256, 13, 20, 15, true, new byte[] { 0, 6, 4 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1171EP1</c>
        /// </summary>
        public static NTRUParameters EES1171EP1FAST = new NTRUParameters(1171, 2048, 8, 7, 11, 106, 0, 256, 13, 20, 15, true, new byte[] { 0, 6, 4 }, true, true, Digests.SHA512);
        /// <summary>
        /// A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for encryption/decryption speed.
        /// </summary>
        public static NTRUParameters EES1499EP1 = new NTRUParameters(1499, 2048, 79, 79, 0, 256, 13, 17, 19, true, new byte[] { 0, 6, 5 }, true, false, Digests.SHA512);
        /// <summary>
        /// A product-form version of <c>EES1499EP1</c>
        /// </summary>
        public static NTRUParameters EES1499EP1FAST = new NTRUParameters(1499, 2048, 7, 6, 11, 79, 0, 256, 13, 17, 19, true, new byte[] { 0, 6, 5 }, true, true, Digests.SHA512);
        /// <summary>
        /// A parameter set that gives 128 bits of security and uses simple ternary polynomials.
        /// </summary>
        public static NTRUParameters APR2011439 = new NTRUParameters(439, 2048, 146, 130, 126, 128, 12, 32, 9, true, new byte[] { 0, 7, 101 }, true, false, Digests.SHA256);
        /// <summary>
        /// Like <c>APR2011_439</c>, this parameter set gives 128 bits of security but uses product-form polynomials and <c>f=1+pF</c>.
        /// </summary>
        public static NTRUParameters APR2011439FAST = new NTRUParameters(439, 2048, 9, 8, 5, 130, 126, 128, 12, 32, 9, true, new byte[] { 0, 7, 101 }, true, true, Digests.SHA256);
        /// <summary>
        /// A parameter set that gives 256 bits of security and uses simple ternary polynomials.
        /// </summary>
        public static NTRUParameters APR2011743 = new NTRUParameters(743, 2048, 248, 220, 60, 256, 12, 27, 14, true, new byte[] { 0, 7, 105 }, false, false, Digests.SHA512);
        /// <summary>
        /// Like <c>APR2011_743</c>, this parameter set gives 256 bits of security but uses product-form polynomials and <c>f=1+pF</c>. 
        /// </summary>
        public static NTRUParameters APR2011743FAST = new NTRUParameters(743, 2048, 11, 11, 15, 220, 60, 256, 12, 27, 14, true, new byte[] { 0, 7, 105 }, false, true, Digests.SHA512);
    }
}