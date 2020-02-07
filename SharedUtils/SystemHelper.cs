using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharedUtils {
    public class SystemHelper {

        public static bool IsRunningOnMono() {
            return Type.GetType("Mono.Runtime") != null;
        }

        
    }                         
}
