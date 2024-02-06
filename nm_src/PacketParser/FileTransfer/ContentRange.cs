using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    internal class ContentRange {
        internal long Start;
        internal long End;//last index inside the content range, i.e. range length = end + 1 - start
        internal long Total;
    }
}
