using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharedUtils.Pcap {
    public class Tools {

        public static string GenerateCaptureFileName(DateTime timestamp) {
            return "NM_"+timestamp.ToString("s", System.Globalization.DateTimeFormatInfo.InvariantInfo).Replace(':','-')+".pcap";
        }
    }
}
