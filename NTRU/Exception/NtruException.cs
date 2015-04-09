#region Directives
using System;
#endregion

namespace NTRU.Exceptions
{
    /// <summary>
    /// The libraries base exception type
    /// </summary>
    public class NtruException : Exception
    {
        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Msg">A custom message or error data</param>
        public NtruException(String Msg) : 
            base(Msg)
        {
        }
    }
}