//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    public abstract class AbstractPacketHandler : ICanParse {

        private PacketHandler mainPacketHandler;
        internal PacketHandler MainPacketHandler { get { return this.mainPacketHandler; } }

        public abstract Type ParsedType { get; }

        internal AbstractPacketHandler(PacketHandler mainPacketHandler) {
            this.mainPacketHandler=mainPacketHandler;
        }

        public virtual bool CanParse(HashSet<Type> packetTypeSet) {
            return packetTypeSet.Contains(this.ParsedType);
        }
    }
}
