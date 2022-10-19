//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PacketParser {
    public class NetworkHostList {
        private readonly SortedDictionary<uint, NetworkHost> networkHostDictionary;

        public int Count {
            get {
                lock(this.networkHostDictionary)
                    return networkHostDictionary.Count;
            }
        }
        public ICollection<NetworkHost> Hosts {
            get {
                lock(this.networkHostDictionary)
                    return networkHostDictionary.Values;
            }
        }

        internal NetworkHostList() {
            this.networkHostDictionary = new SortedDictionary<uint, NetworkHost>();
        }

        internal void Clear() {
            lock(this.networkHostDictionary)
                this.networkHostDictionary.Clear();
        }

        internal bool ContainsIP(IPAddress ip) {
            uint ipUint = Utils.ByteConverter.ToUInt32(ip);
            lock (this.networkHostDictionary)
                return networkHostDictionary.ContainsKey(ipUint);
        }

        internal void Add(NetworkHost host) {
            lock(this.networkHostDictionary)
                this.networkHostDictionary.Add(Utils.ByteConverter.ToUInt32(host.IPAddress), host);
        }

        public NetworkHost GetNetworkHost(IPAddress ip) {
            uint ipUint = Utils.ByteConverter.ToUInt32(ip);
            lock (this.networkHostDictionary) {
                if (this.networkHostDictionary.ContainsKey(ipUint))
                    return networkHostDictionary[ipUint];
                else
                    return null;
            }
        }
    }
}
