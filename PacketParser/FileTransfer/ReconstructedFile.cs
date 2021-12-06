//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    public class ReconstructedFile {
        private string md5Sum=null;//uses lazy initialization

        public string FilePath { get; }
        public Uri RelativeUri { get; }//is null if we only have an absolute path
        public FiveTuple FiveTuple { get; }
        public bool TransferIsClientToServer { get; }
        public NetworkHost SourceHost { get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ClientHost;
                else
                    return this.FiveTuple.ServerHost;
            }
        }
        internal ushort SourcePort {
            get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ClientPort;
                else
                    return this.FiveTuple.ServerPort;
            }
        }
        internal ushort DestinationPort {
            get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ServerPort;
                else
                    return this.FiveTuple.ClientPort;
            }
        }
        public string SourcePortString { get { return this.GetTransportProtocol().ToString()+" "+this.SourcePort; } }
        public NetworkHost DestinationHost {
            get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ServerHost;
                else
                    return this.FiveTuple.ClientHost;
            }
        }
        public string DestinationPortString { get { return this.GetTransportProtocol().ToString() + " "+this.DestinationPort; } }
        public string Filename { get; }
        public string ExtensionFromHeader { get; }
        public long FileSize { get; }
        public string FileSizeString {
            get {
                //return string.Format(new 
                System.Globalization.NumberFormatInfo nfi=new System.Globalization.NumberFormatInfo();
                nfi.NumberDecimalDigits=0;
                nfi.NumberGroupSizes=new int[] {3};
                nfi.NumberGroupSeparator=" ";
                //nfi.
                return this.FileSize.ToString("N", nfi)+" B";
            } }
        public string Details { get; }
        public FileStreamTypes FileStreamType { get; }
        public long InitialFrameNumber { get; }
        public DateTime Timestamp { get; }
        public string ServerHostname { get; }

        public string MD5Sum {
            get {
                //this parameter uses lazy initialization
                if(this.md5Sum==null)
                    this.md5Sum=SharedUtils.Md5SingletonHelper.Instance.GetMd5Sum(this.FilePath);
                return this.md5Sum;
            }
        }

        private string GetFileEnding() {
            if(!Filename.Contains("."))
                return "";
            if(Filename.EndsWith("."))
                return "";
            return this.Filename.Substring(Filename.LastIndexOf('.')+1).ToLower();
        }

        public bool IsImage() {
            string fileEnding = this.ExtensionFromHeader;
            if(string.IsNullOrEmpty(fileEnding))
                fileEnding = this.GetFileEnding();
            if(fileEnding.Length==0)
                return false;
            if(fileEnding=="jpg" || fileEnding=="jpeg" || fileEnding=="gif" || fileEnding=="png" || fileEnding=="bmp" || fileEnding=="tif" || fileEnding=="tiff")
                return true;
            else
                return false;
        }

        public bool IsIcon() {
            string fileEnding = this.ExtensionFromHeader;
            if (string.IsNullOrEmpty(fileEnding))
                fileEnding = this.GetFileEnding();
            if (fileEnding.Length==0)
                return false;
            if (fileEnding == "ico" || fileEnding == "icon" || fileEnding == "x-icon")
                return true;
            else if (this.Filename.Contains("favicon")) {
                byte[] b = this.GetHeaderBytes(12);
                if (b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0 && b[4] == 1 && b[5] == 0 && b[9] == 0 && b[11] == 0)
                    return true;
            }
            return false;
        }

        public bool IsMultipartFormData() {
            string fileEnding = this.GetFileEnding();
            if(fileEnding.Length==0)
                return false;
            if(fileEnding=="mime")
                return true;
            else
                return false;
        }



        internal ReconstructedFile(string path, Uri relativeUri, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string details, long initialFrameNumber, DateTime timestamp, string serverHostname, string extensionFromHeader = null) {
            this.FilePath=path;
            this.RelativeUri = relativeUri;
            try {
                if(path.Contains("\\"))
                    this.Filename=path.Substring(path.LastIndexOf('\\')+1);
                else if(path.Contains("/"))
                    this.Filename=path.Substring(path.LastIndexOf('/')+1);
                else
                    this.Filename=path;

            }
            catch(Exception) {
                this.Filename="";
            }
            this.FiveTuple = fiveTuple;
            this.TransferIsClientToServer = transferIsClientToServer;
            /*
            this.sourceHost=sourceHost;
            this.destinationHost=destinationHost;
            this.sourcePort=sourcePort;
            this.destinationPort=destinationPort;
            this.tcpTransfer=tcpTransfer;
            */
            this.FileStreamType=fileStreamType;
            this.Details=details;

            System.IO.FileInfo fi=new System.IO.FileInfo(path);
            this.FileSize=fi.Length;
            this.InitialFrameNumber=initialFrameNumber;
            this.Timestamp=timestamp;
            this.ServerHostname = serverHostname;
            this.ExtensionFromHeader = extensionFromHeader;
            //SharedUtils.Logger.Log("Reconstructed file: " + fi.Name, System.Diagnostics.EventLogEntryType.Information);

        }

        private FiveTuple.TransportProtocol GetTransportProtocol() {
            return this.FiveTuple.Transport;
        }

        public override string ToString() {
            string sourceInfo;
            string destinationInfo;
            sourceInfo=this.SourceHost.ToString()+" " + this.FiveTuple.Transport.ToString() + " " + this.SourcePort;
            destinationInfo=this.DestinationHost.ToString()+ " " + this.FiveTuple.Transport.ToString() + " " + this.DestinationPort;

            return Filename+"\t"+sourceInfo+"\t"+destinationInfo;

        }

        public byte[] GetHeaderBytes(int nBytes) {

            using (System.IO.FileStream fileStream = new System.IO.FileStream(this.FilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite, nBytes, System.IO.FileOptions.SequentialScan)) {

                byte[] bytes = new byte[nBytes];
                int bytesRead = fileStream.Read(bytes, 0, nBytes);
                fileStream.Close();
                if (bytesRead >= nBytes)
                    return bytes;
                else if (bytesRead < 0)
                    return null;
                else { //0 <= bytesRead < nBytes)
                    byte[] b = new byte[bytesRead];
                    Array.Copy(bytes, b, bytesRead);
                    return b;
                }
            }
        }

    }
}
