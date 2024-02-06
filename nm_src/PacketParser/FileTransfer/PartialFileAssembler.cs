using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.FileTransfer {

    /// <summary>
    /// PartialFileAssembler is used by FileStreamAssembler when it has assembled a file that
    /// turns out to only be a fragment of a larger file, for example a range HTTP request.
    /// </summary>
    class PartialFileAssembler : IDisposable {
        private readonly FileStreamAssembler.FileAssmeblyRootLocation fileAssmeblyRootLocation;
        private readonly FiveTuple fiveTuple;
        private readonly bool transferIsClientToServer;
        private readonly FileStreamTypes fileStreamType;
        private string fileLocation;
        private string filename;
        private readonly FileStreamAssemblerList parentAssemblerList;
        private readonly string extendedFileId;
        private readonly SortedList<long, ReconstructedFile> filePartList;
        private readonly long totalFileSize;
        private DateTime timestamp;
        private readonly long initialFrameNumber;
        private readonly string serverHostname;//host header in HTTP

        internal bool IsClosed { get; private set; } = false;

        internal PartialFileAssembler(FileStreamAssembler.FileAssmeblyRootLocation fileAssmeblyRootLocation, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string fileLocation, string filename, FileStreamAssemblerList parentAssemblerList, string extendedFileId, long totalFileSize, long initialFrameNumber, string serverHostname) {
            this.fileAssmeblyRootLocation = fileAssmeblyRootLocation;

            this.fiveTuple = fiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;
            this.fileStreamType = fileStreamType;
            this.fileLocation = fileLocation;
            this.filename = filename;
            this.parentAssemblerList = parentAssemblerList;
            this.extendedFileId = extendedFileId;
            this.totalFileSize = totalFileSize;
            this.filePartList = new SortedList<long, ReconstructedFile>();
            this.initialFrameNumber = initialFrameNumber;
            this.serverHostname = serverHostname;
        }

        internal void AddFile(ReconstructedFile file, ContentRange range) {
            if (this.IsClosed) {
                throw new Exception("The assembler is closed.");
            }
            else {
                this.timestamp = file.Timestamp;
                if (this.filePartList.ContainsKey(range.Start)) {
                    if (this.filePartList[range.Start].FileSize < file.FileSize)
                        this.filePartList[range.Start] = file;
                }
                else
                    this.filePartList.Add(range.Start, file);
            }
        }

        internal bool IsComplete() {
            //here comes the difficult part -- evaluating if we have all parts (may be overlapping).
            long nextOffset = 0;
            foreach (KeyValuePair<long, ReconstructedFile> offsetFile in this.filePartList) {
                if (offsetFile.Key > nextOffset)
                    break;
                else if (nextOffset < offsetFile.Key + offsetFile.Value.FileSize)
                    nextOffset = offsetFile.Key + offsetFile.Value.FileSize;
            }
            if (nextOffset >= this.totalFileSize)
                return true;
            else
                return false;
        }

        internal ReconstructedFile Reassemble(bool setExtensionFromFileHeader = false) {
            string extensionFromHeader = null;
            if (setExtensionFromFileHeader) {
                byte[] fileHeaderData = new byte[1024];
                string firstPartPath = this.filePartList.Values.FirstOrDefault()?.FilePath;
                if (firstPartPath != null && System.IO.File.Exists(firstPartPath)) {
                    using (System.IO.FileStream partStream = new System.IO.FileStream(firstPartPath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, fileHeaderData.Length)) {
                        int bytesRead = partStream.Read(fileHeaderData, 0, fileHeaderData.Length);
                        if (bytesRead >= 8) {
                            if (bytesRead < fileHeaderData.Length)
                                fileHeaderData = fileHeaderData.Take(bytesRead).ToArray();
                            extensionFromHeader = FileStreamAssembler.SetExtensionFromFileHeader(fileHeaderData, ref this.filename, ref this.fileLocation);
                        }
                    }
                }
            }

            (string destinationPath, Uri destinationRelativeUri) = FileStreamAssembler.GetFilePath(this.fileAssmeblyRootLocation, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.fileLocation, this.filename, this.parentAssemblerList, this.extendedFileId);

            ReconstructedFile reconstructedFile = null;
            
            using (System.IO.FileStream fullFileStream = new System.IO.FileStream(destinationPath, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None, 256 * 1024)) {//256 kB buffer is probably a suitable value for good performance on large files
                foreach (KeyValuePair<long, ReconstructedFile> part in this.filePartList) {
                    //if (fullFileStream.Position != part.Key)
                    //    fullFileStream.Seek(part.Key, System.IO.SeekOrigin.Begin);
                    long partOffset = fullFileStream.Position - part.Key;
                    if(partOffset < part.Key + part.Value.FileSize)
                        using (System.IO.FileStream partStream = new System.IO.FileStream(part.Value.FilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, 256*1024)) {
                            if (partOffset > 0)
                                partStream.Seek(partOffset, System.IO.SeekOrigin.Begin);
                            //Stream.CopyTo isn't available in .NET 2.0 so I'll have to copy the data manually
                            byte[] buffer = new byte[4096];
                            int bytesRead = partStream.Read(buffer, 0, buffer.Length);
                            while(bytesRead > 0) {
                                fullFileStream.Write(buffer, 0, bytesRead);
                                bytesRead = partStream.Read(buffer, 0, buffer.Length);
                            }
                            
                        }
                }
                fullFileStream.Close();//so that I can read the full size of the file when creating the ReconstructedFile
                //reconstructedFile = new ReconstructedFile(destinationPath, destinationRelativeUri, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.extendedFileId, this.initialFrameNumber, this.timestamp, this.serverHostname);
                if (!ReconstructedFile.TryGetReconstructedFile(out reconstructedFile, destinationPath, destinationRelativeUri, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.extendedFileId, this.initialFrameNumber, this.timestamp, this.serverHostname)) {
                    if (!string.IsNullOrEmpty(extensionFromHeader))
                        reconstructedFile.ExtensionFromHeader = extensionFromHeader;
                    SharedUtils.Logger.Log("Could not create a reconstructed file for " + destinationPath, SharedUtils.Logger.EventLogEntryType.Warning);
                }
            }
            this.IsClosed = true;
            this.filePartList.Clear();
            return reconstructedFile;
        }

        public void Dispose() {
            this.IsClosed = true;
            this.filePartList.Clear();
        }
    }
}
