//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
//using System.Net;
using System.Net.Sockets;
using System.Net;
using SharedUtils.Pcap;

namespace NetworkWrapper{
    public class SocketSniffer : ISniffer{

        private readonly Socket socket;
        private readonly byte[] buffer;
        private bool snifferActive;

        public PacketReceivedEventArgs.PacketTypes BasePacketType { get; }

        public static event PacketReceivedHandler PacketReceived;

        public SocketSniffer(SocketAdapter adapter) {
            this.BasePacketType = adapter.BasePacketType;

            this.snifferActive = false;
            this.buffer = new byte[65535];

            //this does not seem to work for IPv6 traffic.
            //Others seem to have similar problems: http://social.technet.microsoft.com/Forums/en-US/netfxnetcom/thread/95fba78d-aa40-44df-9575-dc98138455f3
            //I would like to do somthing like this:
            if(adapter.IP.AddressFamily==AddressFamily.InterNetworkV6) {
                this.socket =new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Raw);
                this.socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.HeaderIncluded, true);
            }
            else
                this.socket =new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

            IPEndPoint endPoint=new IPEndPoint(adapter.IP, 0);
            this.socket.Bind(endPoint);
            byte[] optionInValue={1,0,0,0};
            this.socket.IOControl(IOControlCode.ReceiveAll, optionInValue, null);
       }

        public void StartSniffing() {
            IAsyncResult sniffResult= this.socket.BeginReceive(this.buffer, 0, this.buffer.Length, SocketFlags.None, new AsyncCallback(this.ReceivePacketListener), null);
            this.snifferActive=true;
        }

        public void StopSniffing() {
            this.snifferActive=false;

        }

        //destructor
        ~SocketSniffer() {
            if(this.socket !=null)
                this.socket.Close();
        }

        private void ReceivePacketListener(IAsyncResult result) {
            int received = this.socket.EndReceive(result);
            try {
                byte[] data = new byte[received];
                Array.Copy(this.buffer, 0, data, 0, received);

                PacketReceivedEventArgs eventArgs = new PacketReceivedEventArgs(data, DateTime.Now, this.BasePacketType);
                PacketReceived(this, eventArgs);
            }
            catch {
                // invalid packet; ignore
            }
            if (this.snifferActive)
                this.socket.BeginReceive(this.buffer, 0, this.buffer.Length, SocketFlags.None, new AsyncCallback(this.ReceivePacketListener), null);
        }
    }
}
