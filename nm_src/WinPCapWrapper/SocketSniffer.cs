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
        private bool disposedValue;

        public PacketReceivedEventArgs.PacketTypes BasePacketType { get; }

        public static event PacketReceivedHandler PacketReceived;

        public SocketSniffer(SocketAdapter adapter) {
            this.BasePacketType = adapter.BasePacketType;

            this.snifferActive = false;
            this.buffer = new byte[65536];

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
            this.socket?.Close();
        }

        private void ReceivePacketListener(IAsyncResult result) {
            int received = 0;
            try {
                received = this.socket.EndReceive(result);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.MessageSize) {
                if (e.ErrorCode == 10040) { //WSAEMSGSIZE
                    SharedUtils.Logger.Log("Warning: Skipped packet larger than " + buffer.Length + ". Consider disabling Large Send Offload (LSO) on NIC.", SharedUtils.Logger.EventLogEntryType.Warning);
                }
                else {
                    SharedUtils.Logger.Log("SocketException: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    throw;
                }
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.IOPending) {
                //997
                /**
                * From the .NET source code:
                * I have guarantees from Brad Williamson that WSARecvMsg() will never return WSAEMSGSIZE directly, since a completion
                * is queued in this case.  We wouldn't be able to handle this easily because of assumptions OverlappedAsyncResult
                * makes about whether there would be a completion or not depending on the error code.  If WSAEMSGSIZE would have been
                * normally returned, it returns WSA_IO_PENDING instead.  That same map is implemented here just in case.
                * */
                SharedUtils.Logger.Log("Warning: Skipped packet due to IOPending", SharedUtils.Logger.EventLogEntryType.Warning);
            }
            catch (Exception e) {
                SharedUtils.Logger.Log(e.ToString(), SharedUtils.Logger.EventLogEntryType.Error);
                throw;
            }
            if (received > 0) {
                try {
                    byte[] data = new byte[received];
                    Array.Copy(this.buffer, 0, data, 0, received);

                    PacketReceivedEventArgs eventArgs = new PacketReceivedEventArgs(data, DateTime.UtcNow, this.BasePacketType);
                    PacketReceived(this, eventArgs);
                }
                catch {
                    // invalid packet; ignore
                }
            }
            if (this.snifferActive)
                this.socket.BeginReceive(this.buffer, 0, this.buffer.Length, SocketFlags.None, new AsyncCallback(this.ReceivePacketListener), null);
        }

        protected virtual void Dispose(bool disposing) {
            if (!disposedValue) {
                if (disposing) {
                    try {
                        this.socket?.Close();
                    }
                    catch (Exception e){
                        SharedUtils.Logger.Log("Error closing socket when disposing sniffer: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                    }
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        public void Dispose() {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
