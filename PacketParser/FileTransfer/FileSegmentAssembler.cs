using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    public class FileSegmentAssembler {

        internal string GetSessionFileID(Guid fileId, NetworkTcpSession tcpSession) {
            return tcpSession.GetFlowID() + "|" + fileId.ToString();
        }

        /*
        private NetworkHost SourceHost {
            get {
                if (this.fileTransferIsServerToClient)
                    return this.networkTcpSession.ServerHost;
                else
                    return this.networkTcpSession.ClientHost;
            }
        }
        private NetworkHost DestinationHost {
            get {
                if (this.fileTransferIsServerToClient)
                    return this.networkTcpSession.ClientHost;
                else
                    return this.networkTcpSession.ServerHost;
            }
        }
        private ushort SourcePort { get {
                if (this.fileTransferIsServerToClient)
                    return this.networkTcpSession.ServerTcpPort;
                else
                    return this.networkTcpSession.ClientTcpPort;
            }
        }
        private ushort DestinationPort { get {
                if (this.fileTransferIsServerToClient)
                    return this.networkTcpSession.ClientTcpPort;
                else
                    return this.networkTcpSession.ServerTcpPort;
            }
        }
        */

        //private Guid fileId;
        //private NetworkTcpSession networkTcpSession;
        //private NetworkHost sourceHost, destinationHost;
        //private ushort sourcePort, destinationPort;
        FiveTuple fiveTuple;
        private bool transferIsClientToServer;
        private long fileSize = -1;//negative = unknown
        private string fileOutputDirectory;
        //private bool fileTransferIsServerToClient;
        //private string uniqueFileId;
        
        private System.IO.FileStream fileStream = null;
        private string tempFilePath;
        private string uniqueFileId;//key in parentAssemblerList
        private PopularityList<string, PacketParser.FileTransfer.FileSegmentAssembler> parentAssemblerList;
        private FileTransfer.FileStreamAssemblerList fileStreamAssemblerList;
        private FileStreamTypes fileStreamType;
        private string details;//human readable info about the file transfer
        private long initialFrameNumber = -1;
        private DateTime initialTimeStamp = DateTime.MinValue;
        private string serverHostname;//host header in HTTP
        private SortedDictionary<long, int> segmentOffsetBytesWritten;

        internal string FilePath { get; set; }
        internal string ContentEncoding = null;
        internal string ContentType = null;
        internal long FileSize { set { this.fileSize = value; } }
        internal string FileOutputDirectory { get { return fileOutputDirectory; } }

        internal FileSegmentAssembler(string fileOutputDirectory, NetworkTcpSession networkTcpSession, bool transferIsClientToServer, string filePath, string uniqueFileId, FileTransfer.FileStreamAssemblerList fileStreamAssemblerList, PopularityList<string, PacketParser.FileTransfer.FileSegmentAssembler> parentAssemblerList, FileStreamTypes fileStreamType, string details, string serverHostname)
            : this(fileOutputDirectory, filePath, uniqueFileId, fileStreamAssemblerList, parentAssemblerList, fileStreamType, details, serverHostname) {
            //this.fileOutputDirectory = fileOutputDirectory;

            //this.networkTcpSession = networkTcpSession;
            this.fiveTuple = networkTcpSession.Flow.FiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;

        }

        internal FileSegmentAssembler(string fileOutputDirectory, bool transferIsClientToServer, string filePath, string uniqueFileId, FileTransfer.FileStreamAssemblerList fileStreamAssemblerList, PopularityList<string, PacketParser.FileTransfer.FileSegmentAssembler> parentAssemblerList, FileStreamTypes fileStreamType, string details, FiveTuple fiveTuple, string serverHostname)
            : this(fileOutputDirectory, filePath, uniqueFileId, fileStreamAssemblerList, parentAssemblerList, fileStreamType, details, serverHostname) {
            this.fiveTuple = fiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;
        }

        private FileSegmentAssembler(string fileOutputDirectory, string filePath, string uniqueFileId, FileTransfer.FileStreamAssemblerList fileStreamAssemblerList, PopularityList<string, PacketParser.FileTransfer.FileSegmentAssembler> parentAssemblerList, FileStreamTypes fileStreamType, string details, string serverHostname) {
            this.fileOutputDirectory = fileOutputDirectory;
            //this.fileTransferIsServerToClient = fileTransferIsServerToClient;
            this.FilePath = filePath;
            this.uniqueFileId = uniqueFileId;
            this.parentAssemblerList = parentAssemblerList;
            this.fileStreamAssemblerList = fileStreamAssemblerList;
            this.fileStreamType = fileStreamType;
            this.details = details;
            this.serverHostname = serverHostname;
            this.segmentOffsetBytesWritten = new SortedDictionary<long, int>();
        }

        internal void AddData(byte[] fileData, Frame frame) {
            if(this.fileStream == null)
                this.AddData(0, fileData, frame);
            else
                this.AddData(this.fileStream.Position, fileData, frame);
        }

        internal void AddData(long fileOffset, byte[] fileData, Frame frame) {
            if (this.initialFrameNumber < 0 || frame.FrameNumber < this.initialFrameNumber) {
                this.initialFrameNumber = frame.FrameNumber;
                this.initialTimeStamp = frame.Timestamp;
            }

            if (this.fileStream == null) {
                this.tempFilePath = FileStreamAssembler.GetFilePath(FileStreamAssembler.FileAssmeblyRootLocation.cache, this.fiveTuple, this.transferIsClientToServer, FileStreamTypes.SMB2, "", this.FilePath, this.fileStreamAssemblerList, uniqueFileId.GetHashCode().ToString("X4") + "-" + Utils.StringManglerUtil.ConvertToFilename(FilePath, 20)).absolutPath;

                this.fileStream = new System.IO.FileStream(tempFilePath, System.IO.FileMode.OpenOrCreate, System.IO.FileAccess.Write, System.IO.FileShare.None, 256 * 1024);//256 kB buffer is probably a suitable value for good performance on large files
            }
            if (this.fileStream != null && this.fileStream.CanWrite) {
                if (fileStream.Position != fileOffset)
                    fileStream.Seek(fileOffset, System.IO.SeekOrigin.Begin);

                fileStream.Write(fileData, 0, fileData.Length);
                if (this.segmentOffsetBytesWritten.ContainsKey(fileOffset))
                    this.segmentOffsetBytesWritten[fileOffset] = Math.Max(fileData.Length, this.segmentOffsetBytesWritten[fileOffset]);
                else
                    this.segmentOffsetBytesWritten.Add(fileOffset, fileData.Length);
                //check if we have 100% of the file
                long index = 0;
                foreach(var kvp in this.segmentOffsetBytesWritten) {
                    if (kvp.Key < index)
                        break;
                    index = Math.Max(index, kvp.Key + kvp.Value);
                }
                if (index > 0 && index == this.fileSize)
                    this.AssembleAndClose();
            }
        }

        internal void Close() {
            if (this.fileStream != null)
                this.fileStream.Close();

            if (this.parentAssemblerList != null)
                this.parentAssemblerList.Remove(this.uniqueFileId);
            this.segmentOffsetBytesWritten.Clear();
        }

        internal void AssembleAndClose() {
            //TODO release all file handles and flush data to disk and move file from cache to server/port directory
            this.Close();

            string fixedFilename = this.FilePath;//no directory info
            string fixedFileLocation = "";
            FileStreamAssembler.FixFilenameAndLocation(ref fixedFilename, ref fixedFileLocation);

            string destinationPath;
            Uri relativeUri;
            //reassemble the files at the server, regardless if they were downloaded from there or uploaded to the server
            if(this.transferIsClientToServer)
                (destinationPath, relativeUri) = FileStreamAssembler.GetFilePath(FileStreamAssembler.FileAssmeblyRootLocation.destination, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, fixedFileLocation, fixedFilename, this.fileStreamAssemblerList, "");
            else
                (destinationPath, relativeUri) = FileStreamAssembler.GetFilePath(FileStreamAssembler.FileAssmeblyRootLocation.source, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, fixedFileLocation, fixedFilename, this.fileStreamAssemblerList, "");
                

            //I need to create the directory here since the file might either be moved to this located or a new file will be created there from a stream
            //string directoryName = destinationPath.Substring(0, destinationPath.Length - fixedFilename.Length);
            string directoryName = System.IO.Path.GetDirectoryName(destinationPath);

            if (!System.IO.Directory.Exists(directoryName)) {
                try {
                    System.IO.Directory.CreateDirectory(directoryName);
                }
                catch (Exception e) {
                    this.fileStreamAssemblerList.PacketHandler.OnAnomalyDetected("Error creating directory \"" + directoryName + "\" for path \"" + destinationPath + "\".\n" + e.Message);
                }
            }


            //files which are already completed can simply be moved to their final destination
            if (this.fileStream != null)
                this.fileStream.Close();
            try {
                //string tmpPath = this.tempFilePath;
                if (System.IO.File.Exists(this.tempFilePath)) {
                    if (this.ContentEncoding == "gzip") {
                        using (System.IO.FileStream compressedStream = new System.IO.FileStream(this.tempFilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read)) {
                            using (System.IO.Compression.GZipStream decompressedStream = new System.IO.Compression.GZipStream(compressedStream, System.IO.Compression.CompressionMode.Decompress)) {
                                using (System.IO.FileStream destinationStream = new System.IO.FileStream(destinationPath, System.IO.FileMode.CreateNew)) {
                                    decompressedStream.CopyTo(destinationStream);
                                }
                            }
                        }
                    }
                    else
                        System.IO.File.Move(this.tempFilePath, destinationPath);
                }
            }
            catch (Exception e) {
                
                this.fileStreamAssemblerList.PacketHandler.OnAnomalyDetected("Error moving file \"" + this.tempFilePath + "\" to \"" + destinationPath + "\". " + e.Message);
            }
            
            if (System.IO.File.Exists(destinationPath)) {
                try {


                    ReconstructedFile completedFile = new ReconstructedFile(destinationPath, relativeUri, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.details, this.initialFrameNumber, this.initialTimeStamp, this.serverHostname);
                    this.fileStreamAssemblerList.PacketHandler.AddReconstructedFile(completedFile);
                    //parentAssemblerList.PacketHandler.ParentForm.ShowReconstructedFile(completedFile);
                }
                catch (Exception e) {
                    this.fileStreamAssemblerList.PacketHandler.OnAnomalyDetected("Error creating reconstructed file: " + e.Message);
                }
            }
        }


    }
}
