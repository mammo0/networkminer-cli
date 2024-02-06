using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace SharedUtils {
    internal class SortableIpAddress : IPAddress, IComparable, IComparable<SortableIpAddress>, IComparable<IPAddress> {

        public static bool TryParse(string ipString, out SortableIpAddress address) {
            bool result = IPAddress.TryParse(ipString, out IPAddress ipAddress);
            if (result)
                address = new SortableIpAddress(ipAddress);
            else
                address = null;
            return result;
        }

        public static new SortableIpAddress Parse(string ipString) {
            IPAddress ipAdress = IPAddress.Parse(ipString);
            return new SortableIpAddress(ipAdress);
        }

        public SortableIpAddress(IPAddress ipAddress) : this(ipAddress.GetAddressBytes(), ipAddress.ScopeId) {
        }
        public SortableIpAddress(long newAddress) : base(newAddress) {
        }

        public SortableIpAddress(byte[] address) : base(address) {
        }

        public SortableIpAddress(byte[] address, long scopeid) : base(address, scopeid) {
        }

        public int CompareTo(object other) {
            if (other is IPAddress otherIpAddress)
                return this.CompareTo(otherIpAddress);
            else
                throw new NotImplementedException();
        }

        public int CompareTo(SortableIpAddress other) {
            return this.CompareTo((IPAddress)other);
        }

        public int CompareTo(IPAddress otherIpAddress) {
            if (base.AddressFamily != otherIpAddress.AddressFamily)
                return base.AddressFamily - otherIpAddress.AddressFamily;
            byte[] localBytes = base.GetAddressBytes();
            byte[] remoteBytes = otherIpAddress.GetAddressBytes();
            for (int i = 0; i < localBytes.Length; i++) {
                if (localBytes[i] != remoteBytes[i])
                    return localBytes[i] - remoteBytes[i];
            }
            return 0;
        }

    }
}
