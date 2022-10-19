using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Utils {
    public class SystemHelper {

        [Obsolete("Use SharedUtils.SystemHelper.IsRunningOnMono() instead")]
        public static bool IsRunningOnMono() {
            //return Type.GetType("Mono.Runtime") != null;
            return SharedUtils.SystemHelper.IsRunningOnMono();
        }

        
    }                         
}
