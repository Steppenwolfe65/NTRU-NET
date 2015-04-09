#region Directives
using System;
using System.IO;
using NTRU.Encrypt;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace Test.Tests.Encrypt
{
    /// <summary>
    /// Test the validity of the EncryptionKey implementation
    /// </summary>
    public class NtruKeyTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the EncryptionKey implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! EncryptionKey tests have executed succesfully.";
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
        /// Tests the validity of the EncryptionKey implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                Encode();
                OnProgress(new TestEventArgs("Passed encryption key comparison tests"));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private Methods
        private void Encode()
        {
            foreach (NtruParameters param in new NtruParameters[] { 
                DefinedParameters.APR2011743, 
                DefinedParameters.APR2011743FAST, 
                DefinedParameters.EES1499EP1})
                    Encode(param);
        }

        private void Encode(NtruParameters param)
        {
            NtruEncrypt ntru = new NtruEncrypt(param);
            NtruKeyPair kp = ntru.GenerateKeyPair();
            byte[] priv = kp.PrivateKey.GetEncoded();
            byte[] pub = kp.PublicKey.GetEncoded();
            NtruKeyPair kp2 = new NtruKeyPair(new NtruPrivateKey(priv), new NtruPublicKey(pub));
            if (!Compare.Equals(kp.PublicKey, kp2.PublicKey))
                throw new Exception("EncryptionKey: public key comparison test failed!");
            if (!Compare.Equals(kp.PrivateKey, kp2.PrivateKey))
                throw new Exception("EncryptionKey: private key comparison test failed!");

            MemoryStream bos1 = new MemoryStream();
            MemoryStream bos2 = new MemoryStream();
            kp.PrivateKey.WriteTo(bos1);
            kp.PublicKey.WriteTo(bos2);
            MemoryStream bis1 = new MemoryStream(bos1.ToArray());
            MemoryStream bis2 = new MemoryStream(bos2.ToArray());
            NtruKeyPair kp3 = new NtruKeyPair(new NtruPrivateKey(bis1), new NtruPublicKey(bis2));
            if (!Compare.Equals(kp.PublicKey, kp3.PublicKey))
                throw new Exception("EncryptionKey: public key comparison test failed!");
            if (!Compare.Equals(kp.PrivateKey, kp3.PrivateKey))
                throw new Exception("EncryptionKey: private key comparison test failed!");
        }
        #endregion
    }
}