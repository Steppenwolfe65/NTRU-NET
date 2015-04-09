#region Directives
using System;
using System.IO;
using NTRU.Encrypt;
using NTRU.Polynomial;
using VTDev.Libraries.CEXEngine.Utility;
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
            NtruParameters[] paramSets = new NtruParameters[] 
            { 
                DefinedParameters.APR2011439,
                DefinedParameters.APR2011439FAST,
                DefinedParameters.APR2011743FAST,
                DefinedParameters.EES1087EP2,
                DefinedParameters.EES1499EP1,
            };

            foreach (NtruParameters ep in paramSets)
            {
                NtruEncrypt ntru = new NtruEncrypt(ep);
                NtruKeyPair kp1 = ntru.GenerateKeyPair();
                if (!Compare.True(kp1.IsValid()))
                    throw new Exception("NtruKeyPair generated key pair is invalid!");
            }

            // test an invalid key pair
            NtruParameters param = DefinedParameters.APR2011439;
            NtruEncrypt ntru2 = new NtruEncrypt(param);
            NtruKeyPair kp = ntru2.GenerateKeyPair();
            kp.PublicKey.H.Coeffs[55]++;
            if (!Compare.False(kp.IsValid()))
                throw new Exception("NtruKeyPair coefficients comparison failed!");

            kp.PublicKey.H.Coeffs[55]--;
            IntegerPolynomial t = kp.PrivateKey.T.ToIntegerPolynomial();
            t.Coeffs[66]++;
            kp.PrivateKey.T = t;
            if (!Compare.False(kp.IsValid()))
                throw new Exception("NtruKeyPair T comparison failed!");
        }

        private void Encode()
        {
            NtruParameters[] paramSets = new NtruParameters[] 
            {
                DefinedParameters.APR2011439,
                DefinedParameters.APR2011439FAST,
                DefinedParameters.APR2011743FAST,
                DefinedParameters.EES1087EP2,
                DefinedParameters.EES1499EP1,
            };

            foreach (NtruParameters param in paramSets)
                Encode(param);
        }

        private void Encode(NtruParameters param)
        {
            NtruEncrypt ntru = new NtruEncrypt(param);
            NtruKeyPair kp = ntru.GenerateKeyPair();

            // encode to byte[] and reconstruct
            byte[] enc = kp.GetEncoded();
            NtruKeyPair kp2 = new NtruKeyPair(enc);
            if (!Compare.Equals(kp, kp2))
                throw new Exception("NtruKeyPair encoding test failed!");

            // encode to OutputStream and reconstruct
            MemoryStream bos = new MemoryStream();
            kp.WriteTo(bos);
            MemoryStream bis = new MemoryStream(bos.ToArray());
            NtruKeyPair kp3 = new NtruKeyPair(bis);
            if (!Compare.Equals(kp, kp3))
                throw new Exception("NtruKeyPair encoding test failed!");
        }
        #endregion
    }
}