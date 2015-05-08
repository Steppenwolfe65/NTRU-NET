#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Exceptions
{
    /// <summary>
    /// The libraries base exception type
    /// </summary>
    public class NTRUException : Exception
    {
        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Msg">A custom message or error data</param>
        public NTRUException(String Msg) : 
            base(Msg)
        {
        }
    }
}