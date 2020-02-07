using System;
using System.Collections.Generic;
using System.Text;

namespace NetresecShared.Pcap {
    public class Tools {

        public static string GenerateCaptureFileName(DateTime timestamp) {
            return "NM_"+timestamp.ToString("s", System.Globalization.DateTimeFormatInfo.InvariantInfo).Replace(':','-')+".pcap";
        }

        

        
    }
}
