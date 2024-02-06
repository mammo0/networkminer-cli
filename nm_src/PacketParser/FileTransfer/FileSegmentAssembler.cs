using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    /// <summary>
    /// FileSegmentAssembler is suitable for file transfer protocols where file contents
    /// is transmitted in small segments with protocol headers on them. Handlers of such
    /// protocols can have a local FileSegmentAssembler that can help them assemble files
    /// from the transmitted segments.
    /// </summary>
    public class FileSegmentAssembler {

        internal string GetSessionFileID(Guid fileId, NetworkTcpSession tcpSession) {
            return tcpSession.GetFlowID() + "|" + fileId.ToString();
        }

        readonly FiveTuple fiveTuple;
        private readonly bool transferIsClientToServer;
        private System.IO.FileStream fileStream = null;
        private string tempFilePath;
        private readonly string uniqueFileId;//key in parentAssemblerList
        private readonly PopularityList<string, FileSegmentAssembler> parentAssemblerList;
        private readonly FileStreamAssemblerList fileStreamAssemblerList;
        private readonly FileStreamTypes fileStreamType;
        private readonly string details;//human readable info about the file transfer
        private long initialFrameNumber = -1;
        private DateTime initialTimeStamp = DateTime.MinValue;
        private readonly string serverHostname;//host header in HTTP
        private readonly SortedDictionary<long, int> segmentOffsetBytesWritten;

        internal string FilePath { get; set; }
        internal string ContentEncoding = null;
        internal string ContentType = null;
        internal long SegmentSize { private get;  set; } = -1;//negative = unknown

        internal (string key, ContentRange range)? TotalFileNameAndRange { get; set; } = null;
        internal long TotalFileSize {
            get {
                if (!this.IsPartialFile)
                    return this.SegmentSize;
                else if (this.TotalFileNameAndRange?.range.Total > 0)
                    return this.TotalFileNameAndRange.Value.range.Total;
                else
                    return -1;
            }
        }
        internal bool IsPartialFile {
            get {
                return this.TotalFileNameAndRange?.range != null && this.TotalFileNameAndRange?.range.Total > this.SegmentSize;
            }
        }

        internal string FileOutputDirectory { get; }



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
            this.FileOutputDirectory = fileOutputDirectory;
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
                if (index > 0 && index == this.SegmentSize)
                    this.AssembleAndClose();
                else if (this.SegmentSize > 0 && index > this.SegmentSize)
                    throw new Exception("Segment data exceeds file size");
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
                    if (this.ContentEncoding == "gzip")
                    {
                        using (System.IO.FileStream compressedStream = new System.IO.FileStream(this.tempFilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                        {
                            using (System.IO.Compression.GZipStream decompressedStream = new System.IO.Compression.GZipStream(compressedStream, System.IO.Compression.CompressionMode.Decompress))
                            {
                                using (System.IO.FileStream destinationStream = new System.IO.FileStream(destinationPath, System.IO.FileMode.CreateNew))
                                {
                                    decompressedStream.CopyTo(destinationStream);
                                }
                            }
                        }
                    }
                    else {
                        if (this.ContentEncoding == "br" && ! destinationPath.EndsWith(".br")) {//Brotli compression
                            //.NET Core 2.1 and later supports Brotli compression, but not .NET Framework or Windows Desktop
                            //https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.brotlistream?view=netcore-2.1
                            destinationPath += ".br";
                        }
                        System.IO.File.Move(this.tempFilePath, destinationPath);
                    }
                        
                }
            }
            catch (Exception e) {
                
                this.fileStreamAssemblerList.PacketHandler.OnAnomalyDetected("Error moving file \"" + this.tempFilePath + "\" to \"" + destinationPath + "\". " + e.Message);
            }

            if (System.IO.File.Exists(destinationPath)) {



                //ReconstructedFile completedFile = new ReconstructedFile(destinationPath, relativeUri, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.details, this.initialFrameNumber, this.initialTimeStamp, this.serverHostname);
                if (ReconstructedFile.TryGetReconstructedFile(out ReconstructedFile completedFile, destinationPath, relativeUri, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.details, this.initialFrameNumber, this.initialTimeStamp, this.serverHostname)) {
                    try {
                        if (this.fileStreamAssemblerList.PacketHandler.ExtractPartialDownloads || this.IsPartialFile == false || this.SegmentSize == this.TotalFileNameAndRange?.range.Total) {
                            this.fileStreamAssemblerList.PacketHandler.AddReconstructedFile(completedFile);
                            //parentAssemblerList.PacketHandler.ParentForm.ShowReconstructedFile(completedFile);
                        }

                        if (this.IsPartialFile) {

                            //this code is also in FileStreamAssembler

                            string fileKey = this.TotalFileNameAndRange.Value.key;
                            PartialFileAssembler partialFileAssembler;

                            if (this.fileStreamAssemblerList.PartialFileAssemblerList.ContainsKey(fileKey))
                                partialFileAssembler = this.fileStreamAssemblerList.PartialFileAssemblerList[fileKey];
                            else {
                                FileStreamAssembler.FileAssmeblyRootLocation fileLocation;
                                if (this.transferIsClientToServer)
                                    fileLocation = FileStreamAssembler.FileAssmeblyRootLocation.destination;
                                else
                                    fileLocation = FileStreamAssembler.FileAssmeblyRootLocation.source;
                                partialFileAssembler = new PartialFileAssembler(fileLocation, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, "", this.TotalFileNameAndRange.Value.key, this.fileStreamAssemblerList, this.details, this.TotalFileSize, initialFrameNumber, this.serverHostname);
                                this.fileStreamAssemblerList.PartialFileAssemblerList.Add(fileKey, partialFileAssembler);
                            }

                            partialFileAssembler.AddFile(completedFile, this.TotalFileNameAndRange.Value.range);

                            if (partialFileAssembler.IsComplete()) {
                                ReconstructedFile reconstructedFile = partialFileAssembler.Reassemble(true);
                                this.fileStreamAssemblerList.PartialFileAssemblerList.Remove(fileKey);
                                if (reconstructedFile != null) {

                                    this.fileStreamAssemblerList.PacketHandler.AddReconstructedFile(reconstructedFile);
                                    //this.FileReconstructed?.Invoke(this.extendedFileId, reconstructedFile);
                                }
                            }
                        }
                    }
                    catch (Exception e) {
                        this.fileStreamAssemblerList.PacketHandler.OnAnomalyDetected("Error creating reconstructed file: " + e.Message);
                    }
                }



            }
        }


    }
}
