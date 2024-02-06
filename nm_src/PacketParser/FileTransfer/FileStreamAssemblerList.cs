//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    public class FileStreamAssemblerList : PopularityList<string, FileStreamAssembler> {

        private const int QUEUE_SIZE = 100;

        internal static System.Collections.Concurrent.ConcurrentBag<IDisposable> TempFileHandlers = new System.Collections.Concurrent.ConcurrentBag<IDisposable>();

        public static void RemoveTempFiles() {
            foreach (IDisposable disposable in TempFileHandlers) {
                try {
                    disposable.Dispose();
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Exception when disposing Temp file: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                }
            }
            TempFileHandlers = new System.Collections.Concurrent.ConcurrentBag<IDisposable>();
        }

        private readonly PopularityList<string, Queue<FileStreamAssembler>> fileStreamAssemblerQueue;

        internal bool DecompressGzipStreams { get; }
        internal string FileOutputDirectory { get; }
        internal PacketHandler PacketHandler { get; }
        internal PopularityList<string, PartialFileAssembler> PartialFileAssemblerList { get; }




        internal FileStreamAssemblerList(PacketHandler packetHandler, int maxPoolSize, string fileOutputDirectory)
            : base(maxPoolSize) {
            this.PacketHandler = packetHandler;
            this.DecompressGzipStreams = true;//this should be a setting that can be changed in an option-menu.
            this.FileOutputDirectory = System.IO.Path.GetDirectoryName(fileOutputDirectory);
            this.PartialFileAssemblerList = new PopularityList<string, PartialFileAssembler>(QUEUE_SIZE);
            this.fileStreamAssemblerQueue = new PopularityList<string, Queue<FileStreamAssembler>>(QUEUE_SIZE);
        }

        private string GetAssemblerId(FileStreamAssembler assembler) {
            return this.GetAssemblerId(assembler.FiveTuple, assembler.TransferIsClientToServer, assembler.ExtendedFileId);
        }

        private string GetAssemblerId(FiveTuple fiveTuple, bool transferIsClientToServer, string extendedFileId = "") {
            return fiveTuple.ToString(transferIsClientToServer) + extendedFileId;
        }

        internal bool ContainsAssembler(FileStreamAssembler assembler) {
            string id = this.GetAssemblerId(assembler);
            return this.ContainsAssembler(id, false);
        }


        internal bool ContainsAssembler(FiveTuple fiveTuple, bool transferIsClientToServer, bool assemblerIsAcive, FileStreamTypes fileStreamType) {
            string id = this.GetAssemblerId(fiveTuple, transferIsClientToServer);
            return (base.ContainsKey(id) && base[id].FileStreamType == fileStreamType && base[id].IsActive == assemblerIsAcive);
        }


        internal bool ContainsAssembler(FiveTuple fiveTuple, bool transferIsClientToServer) {
            string id = this.GetAssemblerId(fiveTuple, transferIsClientToServer);
            return this.ContainsAssembler(id, false);
        }


        internal bool ContainsAssembler(FiveTuple fiveTuple, bool transferIsClientToServer, bool assemblerMustBeActive) {
            string id = this.GetAssemblerId(fiveTuple, transferIsClientToServer);
            return this.ContainsAssembler(id, assemblerMustBeActive);
        }

        private bool ContainsAssembler(string assemblerId, bool assemblerMustBeActive) {
            return (base.ContainsKey(assemblerId) && (!assemblerMustBeActive || base[assemblerId].IsActive));
        }


        internal void Remove(FileStreamAssembler assembler, bool closeAssembler) {
            string id = this.GetAssemblerId(assembler);
            if (base.ContainsKey(id))
                base.Remove(id);
            if (closeAssembler)//it should sometimes be closed elsewhere
                assembler.Clear();
            if (this.fileStreamAssemblerQueue.ContainsKey(id) && this.fileStreamAssemblerQueue[id].Count > 0)
                base.Add(id, this.fileStreamAssemblerQueue[id].Dequeue());
        }



        internal FileStreamAssembler GetAssembler(FiveTuple fiveTuple, bool transferIsClientToServer, string extendedFileId = null) {
            string id = this.GetAssemblerId(fiveTuple, transferIsClientToServer, extendedFileId);
            return base[id];
        }

        internal IEnumerable<FileStreamAssembler> GetAssemblers(NetworkHost sourceHost, NetworkHost destinationHost, FileStreamTypes fileStreamType, bool isActive) {
            foreach (FileStreamAssembler assembler in base.GetValueEnumerator()) {
                if (assembler.IsActive == isActive && assembler.SourceHost == sourceHost && assembler.DestinationHost == destinationHost && assembler.FileStreamType == fileStreamType)
                    yield return assembler;
            }
            yield break;
        }

        /// <summary>
        /// This function can be used instead of Add() if there might already be an active file transfer
        /// for the session. The new queued assembler will then wait for the first one to complete before
        /// being activated.
        /// </summary>
        /// <param name="assembler"></param>
        internal void AddOrEnqueue(FileStreamAssembler assembler) {
            string id = this.GetAssemblerId(assembler);
            if (this.ContainsAssembler(id, false)) {
                if (this.fileStreamAssemblerQueue.ContainsKey(id))
                    this.fileStreamAssemblerQueue[id].Enqueue(assembler);
                else {
                    Queue<FileStreamAssembler> q = new Queue<FileStreamAssembler>();
                    q.Enqueue(assembler);
                    this.fileStreamAssemblerQueue.Add(id, q);
                }
            }
            else this.Add(assembler);
        }

        internal void Add(FileStreamAssembler assembler) {
            string id = this.GetAssemblerId(assembler);

            base.Add(id, assembler);
        }

        public new void Clear() {
            this.Clear(false);
        }

        //Removes all data and stored files
        public void Clear(bool removeExtractedFilesFromDisk) {
            RemoveTempFiles();

            foreach (FileStreamAssembler assembler in base.GetValueEnumerator())
                assembler.Clear();
            base.Clear();

            this.PartialFileAssemblerList.Clear();
            this.fileStreamAssemblerQueue.Clear();

            if (removeExtractedFilesFromDisk) {
                //remove all files
                foreach (string subDirectory in System.IO.Directory.GetDirectories(this.FileOutputDirectory)) {
                    if (subDirectory == this.FileOutputDirectory + System.IO.Path.DirectorySeparatorChar + "cache") {
                        foreach (string cacheFile in System.IO.Directory.GetFiles(subDirectory))
                            try {
                                System.IO.File.Delete(cacheFile);
                            }
                            catch (Exception e) {
                                this.PacketHandler.OnAnomalyDetected("Error deleting file \"" + cacheFile + "\"");
                                SharedUtils.Logger.Log("Exception when deleting file: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                            }
                    }
                    else {
                        try {
                            System.IO.Directory.Delete(subDirectory, true);
                        }
                        catch (Exception e) {
                            this.PacketHandler.OnAnomalyDetected("Error deleting directory \"" + subDirectory + "\"");
                            SharedUtils.Logger.Log("Exception when deleting directory: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                        }
                    }
                }
            }
        }
    }
}
