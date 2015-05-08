#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace Test.Tests.Encrypt
{
    /// <summary>
    /// Test the validity of the NtruKeyPair implementation
    /// </summary>
    public class NtruKeyPairTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the NtruKeyPair implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! NtruKeyPair tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// NtruKeyPair tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                IsValid();
                OnProgress(new TestEventArgs("Passed generated key pair validation tests"));
                Encode();
                OnProgress(new TestEventArgs("Passed keypair encoding tests"));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }

        private void IsValid()
        {
            // test valid key pairs
            NTRUParameters[] paramSets = new NTRUParameters[] 
            { 
                NTRUParamSets.APR2011439,
                NTRUParamSets.APR2011439FAST,
                NTRUParamSets.APR2011743FAST,
                NTRUParamSets.EES1087EP2,
                NTRUParamSets.EES1499EP1,
            };

            foreach (NTRUParameters ep in paramSets)
            {
                NTRUKeyGenerator ntru = new NTRUKeyGenerator(ep);
                NTRUKeyPair kp1 = ntru.GenerateKeyPair();
                if (!Compare.True(kp1.IsValid()))
                    throw new Exception("NtruKeyPair generated key pair is invalid!");
            }

            // test an invalid key pair
            NTRUParameters param = NTRUParamSets.APR2011439;
            NTRUKeyGenerator ntru2 = new NTRUKeyGenerator(param);
            NTRUKeyPair kp = ntru2.GenerateKeyPair();
            ((NTRUPublicKey)kp.PublicKey).H.Coeffs[55]++;
            if (!Compare.False(kp.IsValid()))
                throw new Exception("NtruKeyPair coefficients comparison failed!");

            ((NTRUPublicKey)kp.PublicKey).H.Coeffs[55]--;
            IntegerPolynomial t = ((NTRUPrivateKey)kp.PrivateKey).T.ToIntegerPolynomial();
            t.Coeffs[66]++;
            ((NTRUPrivateKey)kp.PrivateKey).T = t;
            if (!Compare.False(kp.IsValid()))
                throw new Exception("NtruKeyPair T comparison failed!");
        }

        private void Encode()
        {
            NTRUParameters[] paramSets = new NTRUParameters[] 
            {
                NTRUParamSets.APR2011439,
                NTRUParamSets.APR2011439FAST,
                NTRUParamSets.APR2011743FAST,
                NTRUParamSets.EES1087EP2,
                NTRUParamSets.EES1499EP1,
            };

            foreach (NTRUParameters param in paramSets)
                Encode(param);
        }

        private void Encode(NTRUParameters param)
        {
            NTRUEncrypt ntru = new NTRUEncrypt(param);
            NTRUKeyPair kp;
            using (NTRUKeyGenerator kg = new NTRUKeyGenerator(param))
                kp = kg.GenerateKeyPair();

            // encode to byte[] and reconstruct
            byte[] enc = kp.ToBytes();
            NTRUKeyPair kp2 = new NTRUKeyPair(enc);
            if (!Compare.Equals(kp, kp2))
                throw new Exception("NtruKeyPair encoding test failed!");

            // encode to OutputStream and reconstruct
            MemoryStream bos = new MemoryStream();
            kp.WriteTo(bos);
            MemoryStream bis = new MemoryStream(bos.ToArray());
            NTRUKeyPair kp3 = new NTRUKeyPair(bis);
            if (!Compare.Equals(kp, kp3))
                throw new Exception("NtruKeyPair encoding test failed!");
        }
        #endregion
    }
}