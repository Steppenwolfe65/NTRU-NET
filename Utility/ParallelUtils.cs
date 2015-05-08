#region Directives
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// This class is a utility class for parallel processing
    /// </summary>
    internal class ParallelUtils
    {
        /// <summary>
        /// Get: Returns true for multi processor system
        /// </summary>
        public static bool IsParallel
        {
            get { return Environment.ProcessorCount > 1; }
        }

        /// <summary>
        /// A parallel While function
        /// </summary>
        /// 
        /// <param name="Condition">The while conditional</param>
        /// <param name="Body">The functions body</param>
        public static void While(Func<bool> Condition, Action Body)
        {
            Parallel.ForEach(IterateUntilFalse(Condition), ignored => Body());
        }

        private static IEnumerable<bool> IterateUntilFalse(Func<bool> condition)
        {
            while (condition()) yield return true;
        }
    }
}
