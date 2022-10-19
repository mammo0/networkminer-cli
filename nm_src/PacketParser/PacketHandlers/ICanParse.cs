using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.PacketHandlers {
    interface ICanParse {
        Type ParsedType { get; }
        bool CanParse(HashSet<Type> packetTypeSet);

    }
}
