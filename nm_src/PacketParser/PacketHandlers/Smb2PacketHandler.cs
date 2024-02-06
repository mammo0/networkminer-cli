using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketParser.Packets;

using static PacketParser.Packets.Smb2Packet;

namespace PacketParser.PacketHandlers {
    class Smb2PacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private PopularityList<string, PacketParser.FileTransfer.FileSegmentAssembler> fileSegmentAssemblerList;
        private PopularityList<string, Packets.Smb2Packet.Smb2Command> requestCache;
        private PopularityList<string, (string filename, long size)> fileIdFilenameMap;
        private readonly string fileOutputDirectory;

        public ApplicationLayerProtocol HandledProtocol {
            get {
                throw new NotImplementedException();
            }
        }

        public override Type[] ParsedTypes { get; } = typeof(Packets.Smb2Packet).GetNestedTypes().Append(typeof(Packets.Smb2Packet)).ToArray();

        public Smb2PacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {

            this.fileSegmentAssemblerList = new PopularityList<string, FileTransfer.FileSegmentAssembler>(100);
            this.fileSegmentAssemblerList.PopularityLost += (k, assembler) => assembler.Close();
            this.requestCache = new PopularityList<string, Smb2Command>(100);
            this.fileIdFilenameMap = new PopularityList<string, (string filename, long size)>(1000);

            this.fileOutputDirectory = System.IO.Path.GetDirectoryName(mainPacketHandler.OutputDirectory);
        }


        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }
            foreach (Packets.AbstractPacket p in packetList) {
                if (p is Smb2Packet) {
                    Smb2Packet smb2 = (Smb2Packet)p;
                    if(smb2.NtStatus != (uint)Smb2Packet.ERROR_CLASS.STATUS_SUCCESS) {
                        System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                        string errorClassName = Enum.GetName(typeof(Smb2Packet.ERROR_CLASS), smb2.NtStatus);
                        if (string.IsNullOrEmpty(errorClassName))
                            parameters.Add("SMB2 Response " + smb2.MessageID.ToString(), "Error");
                        else
                            parameters.Add("SMB2 Response " + smb2.MessageID.ToString(), "Error: " + errorClassName);

                        base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(p.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, p.ParentFrame.Timestamp, "SMB2 Response"));
                        //}
                    }
                }
                else if (p is Smb2TreeConnectRequest) {
                    Packets.Smb2Packet.Smb2TreeConnectRequest treeConnectRequest = (Packets.Smb2Packet.Smb2TreeConnectRequest)p;

                    this.requestCache.Add(GetUniqueMessageId(tcpSession, treeConnectRequest.Smb2Packet.MessageID), treeConnectRequest);

                    destinationHost.AddNumberedExtraDetail("SMB File Share", treeConnectRequest.ShareName);
                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                    parameters.Add("SMB2 Connect Request " + treeConnectRequest.Smb2Packet.MessageID, treeConnectRequest.ShareName);
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(p.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, p.ParentFrame.Timestamp, "SMB2 Tree Connect Request"));

                }
                else if (p is Smb2TreeConnectResponse) {
                    Packets.Smb2Packet.Smb2TreeConnectResponse treeConnectResponse = (Packets.Smb2Packet.Smb2TreeConnectResponse)p;
                    string requestId = GetUniqueMessageId(tcpSession, treeConnectResponse.Smb2Packet.MessageID);
                    if (this.requestCache.ContainsKey(requestId)) {
                        //checking for STATUS_SUCCESS is also done in Sm2Packet.GetSubPackets, so ERROR_CLASS should always be STATUS_SUCCESS                        
                        if (treeConnectResponse.Smb2Packet.NtStatus == (uint)Smb2Packet.ERROR_CLASS.STATUS_SUCCESS) {
                            Smb2TreeConnectRequest treeConnectRequest = (Smb2TreeConnectRequest)this.requestCache[requestId];
                            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                            parameters.Add("SMB2 Connect " + treeConnectRequest.Smb2Packet.MessageID.ToString() + " Successful (Tree Id: 0x" + treeConnectResponse.Smb2Packet.TreeId.ToString("x8") + ")", treeConnectRequest.ShareName);
                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(p.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, p.ParentFrame.Timestamp, "SMB2 Tree Connect Response"));
                        }
                    }


                }
                else if (p is Smb2CreateRequest) {
                    Smb2CreateRequest createRequest = (Packets.Smb2Packet.Smb2CreateRequest)p;
                    this.requestCache.Add(GetUniqueMessageId(tcpSession, createRequest.Smb2Packet.MessageID), createRequest);
                    if (!string.IsNullOrEmpty(createRequest.FileName)) {
                        System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                        if(createRequest.CreateDisposition == null)
                            parameters.Add("SMB2 Create Request " + createRequest.Smb2Packet.MessageID, createRequest.FileName);
                        else
                            parameters.Add("SMB2 Create Request " + createRequest.Smb2Packet.MessageID + " " + createRequest.CreateDisposition, createRequest.FileName);
                        base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(p.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, p.ParentFrame.Timestamp, "SMB2 Create Request"));
                    }

                }
                else if (p is Packets.Smb2Packet.Smb2CreateResponse) {
                    Packets.Smb2Packet.Smb2CreateResponse createResponse = (Packets.Smb2Packet.Smb2CreateResponse)p;
                    if (createResponse.IsValidCreateResponse) {
                        Guid fileId = createResponse.FileID;

                        //get request
                        string requestId = GetUniqueMessageId(tcpSession, createResponse.Smb2Packet.MessageID);
                        if (this.requestCache.ContainsKey(requestId)) {
#if DEBUG
                            System.Diagnostics.Debug.Assert(this.requestCache[requestId] is Packets.Smb2Packet.Smb2CreateRequest, "Wrong SMB2 request type for Message ID " + requestId + "!");
#endif
                            Smb2CreateRequest createRequest = (Packets.Smb2Packet.Smb2CreateRequest)this.requestCache[requestId];
                            string filename = createRequest.FileName;
                            if (filename != null && filename.Length > 0) {
                                string uniqueFileId = GetUniqueGuid(tcpSession, fileId);
                                if(createResponse.EndOfFile > 0)
                                    this.fileIdFilenameMap.Add(uniqueFileId, (filename, createResponse.EndOfFile));
                                else
                                    this.fileIdFilenameMap.Add(uniqueFileId, (filename, -1));
                                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection {
                                    { filename, "File ID: " + fileId.ToString() },
                                    { "Allocation Size: ", createResponse.AllocationSize.ToString() },
                                    { "File Size: ", createResponse.EndOfFile.ToString() }
                                };
                                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(p.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, p.ParentFrame.Timestamp, "SMB2 Create Response"));
                            }
                        }
                    }
                }
                else if (p is Smb2ReadRequest) {
                    Smb2ReadRequest readRequest = (Smb2ReadRequest)p;
                    this.requestCache.Add(GetUniqueMessageId(tcpSession, readRequest.Smb2Packet.MessageID), readRequest);
                }
                else if (p is Packets.Smb2Packet.Smb2ReadResponse) {
                    Smb2ReadResponse readResponse = (Smb2ReadResponse)p;

                    //get request
                    string requestId = GetUniqueMessageId(tcpSession, readResponse.Smb2Packet.MessageID);
                    if (this.requestCache.ContainsKey(requestId)) {
#if DEBUG
                        System.Diagnostics.Debug.Assert(this.requestCache[requestId] is Packets.Smb2Packet.Smb2ReadRequest, "Wrong SMB2 request type for Message ID " + requestId + "!");
#endif
                        Smb2ReadRequest readRequest = (Packets.Smb2Packet.Smb2ReadRequest)this.requestCache[requestId];
                        Guid fileId = readRequest.FileId;
                        FileTransfer.FileSegmentAssembler assembler = this.GetOrCreateAssembler(tcpSession, false, fileId, OP_CODE.Read);
                        if (assembler != null)
                            assembler.AddData(readRequest.FileOffset, readResponse.FileData, p.ParentFrame);
                    }
                }
                else if (p is Smb2WriteRequest writeRequest) {
                    Guid fileId = writeRequest.FileID;
                    long fileOffset = writeRequest.FileOffset;
                    byte[] fileData = writeRequest.FileData;
                    FileTransfer.FileSegmentAssembler assembler = this.GetOrCreateAssembler(tcpSession, true, fileId, OP_CODE.Write);
                    assembler?.AddData(fileOffset, fileData, p.ParentFrame);
                }
                else if (p is Smb2SetInfoRequest setInfoRequest) {
                    if (setInfoRequest.EndOfFile != null && setInfoRequest.EndOfFile > 0) {
                        Guid fileId = setInfoRequest.FileID;
                        string uniqueFileId = GetUniqueGuid(tcpSession, fileId);
                        if (this.fileIdFilenameMap.ContainsKey(uniqueFileId)) {
                            var fid = this.fileIdFilenameMap[uniqueFileId];
                            this.fileIdFilenameMap[uniqueFileId] = (fid.filename, setInfoRequest.EndOfFile.Value);
                        }

                        FileTransfer.FileSegmentAssembler assembler = this.GetOrCreateAssembler(tcpSession, true, fileId, OP_CODE.SetInfo);
                        if (assembler != null)
                            assembler.SegmentSize = setInfoRequest.EndOfFile.Value;
                        else {

                            this.MainPacketHandler.OnAnomalyDetected("No assembler found for SMB file ID " + fileId + " in frame " + p.ParentFrame.FrameNumber, p.ParentFrame.Timestamp);
                        }
                    }
                }
                else if (p is Smb2CloseRequest closeRequest) {
                    //Guid fileId = closeRequest.FileID;
                    //ulong messageId = closeRequest.Smb2Packet.MessageID;
                    this.requestCache.Add(GetUniqueMessageId(tcpSession, closeRequest.Smb2Packet.MessageID), closeRequest);
                }
                else if (p is Smb2CloseResponse closeResponse) {
                    //get request
                    string requestId = GetUniqueMessageId(tcpSession, closeResponse.Smb2Packet.MessageID);
                    if (this.requestCache.ContainsKey(requestId)) {
#if DEBUG
                        System.Diagnostics.Debug.Assert(this.requestCache[requestId] is Packets.Smb2Packet.Smb2CloseRequest, "Wrong SMB2 request type for Message ID " + requestId + "!");
#endif
                        closeRequest = (Packets.Smb2Packet.Smb2CloseRequest)this.requestCache[requestId];
                        Guid fileId = closeRequest.FileID;
                        //ulong messageId = closeRequest.Smb2Packet.MessageID;
                        long fileSize = closeResponse.EndOfFile;
                        string uniqueFileId = GetUniqueGuid(tcpSession, fileId);
                        if (this.fileSegmentAssemblerList.ContainsKey(uniqueFileId)) {
                            FileTransfer.FileSegmentAssembler assmebler = this.fileSegmentAssemblerList[uniqueFileId];
                            assmebler.SegmentSize = fileSize;
                            assmebler.AssembleAndClose();
                        }
                    }
                }
                else if (p is Smb2FindRequest findRequest) {
                    this.requestCache.Add(GetUniqueMessageId(tcpSession, findRequest.Smb2Packet.MessageID), findRequest);

                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                    parameters.Add("SMB2 Search Pattern", findRequest.SearchPattern);
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(p.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, p.ParentFrame.Timestamp, "SMB2 Find Request"));
                }
                else if (p is Smb2FindResponse findResponse) {
                    findRequest = null;
                    string requestId = GetUniqueMessageId(tcpSession, findResponse.Smb2Packet.MessageID);
                    if (this.requestCache.ContainsKey(requestId)) {
                        findRequest = (Smb2FindRequest)this.requestCache[requestId];
                    }

                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();



                    foreach (Smb2FileInfo fi in findResponse.FileInfoList) {
                        if (fi.Data.Length > 0) {
                            if (findRequest != null && findRequest.InfoLevel == (byte)Smb2Packet.Smb2FindRequest.InfoLevelEnum.NAME_INFO) {
                                Packets.Smb2Packet.Smb2FileNameInfo nameInfoResponse = new Smb2FileNameInfo(fi.Data, 0, fi.Data.Length, findRequest.InfoLevel);
                                parameters.Add("Search result for \"" + findRequest.SearchPattern + "\"", nameInfoResponse.Filename);

                            }
                            else if (findRequest != null && (findRequest.InfoLevel == (byte)Smb2Packet.Smb2FindRequest.InfoLevelEnum.BOTH_DIRECTORY_INFO || findRequest.InfoLevel == (byte)Smb2Packet.Smb2FindRequest.InfoLevelEnum.ID_BOTH_DIRECTORY_INFO)) {
                                Smb2FileBothDirectoryInfo nameInfoResponse = new Smb2FileBothDirectoryInfo(fi.Data, 0, fi.Data.Length, findRequest.InfoLevel);
                                parameters.Add("Search result for \"" + findRequest.SearchPattern + "\"", nameInfoResponse.Filename);
                                parameters.Add(nameInfoResponse.Filename, "Created: " + nameInfoResponse.Created.ToString());
                                parameters.Add(nameInfoResponse.Filename, "Modified: " + nameInfoResponse.Modified.ToString());
                                parameters.Add(nameInfoResponse.Filename, "Accessed: " + nameInfoResponse.Accessed.ToString());

                            }
                            else {
                                //we don't have the findRequest so we don't know what data type the responses are or how to format them
                                //A likely guess is that we're seeing a response of type NAME_INFO, but this isn't very crucial info,
                                //so it's better to just ignore this response. 
                            }
                        }

                    }
                    if (parameters.Count > 0)
                        base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(p.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, p.ParentFrame.Timestamp, "SMB2 File Info"));
                }
            }
            return 0;//NetBiosSessionServicePacketHandler will return the # parsed bytes anyway.
        }

        private FileTransfer.FileSegmentAssembler GetOrCreateAssembler(NetworkTcpSession tcpSession, bool fileTransferIsClientToServer, Guid fileId, OP_CODE smb2Command) {
            string uniqueFileId = GetUniqueGuid(tcpSession, fileId);
            FileTransfer.FileSegmentAssembler assembler = null;
            if (!this.fileSegmentAssemblerList.ContainsKey(uniqueFileId)) {
                if (this.fileIdFilenameMap.ContainsKey(uniqueFileId)) {
                    string filename = this.fileIdFilenameMap[uniqueFileId].filename;
                    assembler = new FileTransfer.FileSegmentAssembler(this.fileOutputDirectory, tcpSession, fileTransferIsClientToServer, filename, uniqueFileId, base.MainPacketHandler.FileStreamAssemblerList, this.fileSegmentAssemblerList, FileTransfer.FileStreamTypes.SMB2, "SMB2 " + Enum.GetName(typeof(OP_CODE), smb2Command) +" " + fileId.ToString() + " \""+ this.fileIdFilenameMap[uniqueFileId]+"\"", null);
                    if (this.fileIdFilenameMap[uniqueFileId].size > 0)
                        assembler.SegmentSize = this.fileIdFilenameMap[uniqueFileId].size;
                    this.fileSegmentAssemblerList.Add(uniqueFileId, assembler);
                }
            }
            else
                assembler = this.fileSegmentAssemblerList[uniqueFileId];
            return assembler;
        }

        private static string GetUniqueMessageId(NetworkTcpSession tcpSession, ulong messageId) {
            return tcpSession.GetFlowID() + "\t" + messageId.ToString();
        }
        private static string GetUniqueGuid(NetworkTcpSession tcpSession, Guid fileId) {
            return tcpSession.GetFlowID() + "\t" + fileId.ToString();
        }

        public void Reset() {
            
            List<PacketParser.FileTransfer.FileSegmentAssembler> assemblers = new List<FileTransfer.FileSegmentAssembler>(this.fileSegmentAssemblerList.GetValueEnumerator());
            foreach (PacketParser.FileTransfer.FileSegmentAssembler fileSegmentAssembler in assemblers)
                fileSegmentAssembler.Close();
                
            fileSegmentAssemblerList.Clear();
            this.requestCache.Clear();
            this.fileIdFilenameMap.Clear();
        }
    }
}
