//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Net;
using System.Collections.Generic;
using System.Text;
using SharedUtils.Pcap;

namespace NetworkMiner {

    internal delegate void NewNetworkHostHandler(PacketParser.NetworkHost host);

    public class PacketHandlerWrapper {

        private NetworkMinerForm parentForm;
        private PcapFileWriter pcapWriter;


        private PacketParser.PacketHandler packetHandler;


        public int CleartextSearchModeSelectedIndex { set { this.packetHandler.CleartextSearchModeSelectedIndex=value; } }
        public PacketParser.PacketHandler PacketHandler { get { return this.packetHandler; } }
        public PcapFileWriter PcapWriter { get { return this.pcapWriter; } set { this.pcapWriter=value; } }


        internal PacketHandlerWrapper(NetworkMinerForm parentForm, bool useRelativePathIfAvailable, List<PacketParser.Fingerprints.IOsFingerprinter> preloadedFingerprints = null)
            : this(parentForm, new System.IO.DirectoryInfo(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath))), useRelativePathIfAvailable, preloadedFingerprints) {
        }

        internal PacketHandlerWrapper(NetworkMinerForm parentForm, System.IO.DirectoryInfo outputDirectory, bool useRelativePathIfAvailable, List<PacketParser.Fingerprints.IOsFingerprinter> preloadedFingerprints) {

            this.parentForm = parentForm;
            this.pcapWriter=null;
            string exePath = System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath);
            if(this.parentForm == null || this.parentForm.GuiProperties == null)
                this.packetHandler = new PacketParser.PacketHandler(exePath, outputDirectory.FullName, preloadedFingerprints, false, NetworkMiner.GuiProperties.ToDefaultTimeZoneString, useRelativePathIfAvailable, this.parentForm.VerifyX509Certificates, NetworkMiner.GuiProperties.MAX_FRAMES_PER_SECOND_VNC_DEFAULT);
            else
                this.packetHandler = new PacketParser.PacketHandler(exePath, outputDirectory.FullName, preloadedFingerprints, false, this.parentForm.GuiProperties.ToCustomTimeZoneString, useRelativePathIfAvailable, this.parentForm.VerifyX509Certificates, parentForm.GuiProperties.MaxFramesPerSecondVNC);

            this.PacketHandler.AnomalyDetected += new PacketParser.AnomalyEventHandler(this.AnomalyDetected);
            this.PacketHandler.BufferUsageChanged+=new PacketParser.BufferUsageEventHandler(this.BufferUsageChanged);
            this.packetHandler.CleartextWordsDetected+=new PacketParser.CleartextWordsEventHandler(this.CleartextWordsDetected);
            this.packetHandler.CredentialDetected+=new PacketParser.CredentialEventHandler(this.CredentialDetected);
            this.packetHandler.DnsRecordDetected+=new PacketParser.DnsRecordEventHandler(this.packetHandler_DnsRecordDetected);
            this.packetHandler.FileReconstructed+=new PacketParser.FileEventHandler(this.packetHandler_FileReconstructed);
            this.packetHandler.FrameDetected+=new PacketParser.FrameEventHandler(this.packetHandler_FrameDetected);
            this.packetHandler.KeywordDetected+=new PacketParser.KeywordEventHandler(this.packetHandler_KeywordDetected);
            this.packetHandler.NetworkHostDetected+=new PacketParser.NetworkHostEventHandler(this.packetHandler_NetworkHostDetected);
            this.packetHandler.HttpTransactionDetected += new PacketParser.HttpClientEventHandler(this.packetHandler_HttpTransactionDetected);
            
            this.packetHandler.ParametersDetected+=new PacketParser.ParameterEventHandler(this.packetHandler_ParametersDetected);
            //this.packetHandler.ParametersDetected += new PacketParser.ParameterEventHandler()
            //this.packetHandler.ParametersDetected += (s, pe) => parentForm.ParametersQueue.Enqueue(pe);

            this.packetHandler.SessionDetected+=new PacketParser.SessionEventHandler(this.packetHandler_SessionDetected);
            this.packetHandler.MessageDetected+=new PacketParser.MessageEventHandler(this.packetHandler_MessageDetected);
            this.packetHandler.AudioDetected += this.PacketHandler_AudioDetected;
            this.packetHandler.VoipCallDetected += this.PacketHandler_VoipCallDetected;

            this.packetHandler.MessageAttachmentDetected += new PacketParser.FileTransfer.FileStreamAssembler.FileReconsructedEventHandler(parentForm.ShowMessageAttachment);
            this.packetHandler.InsufficientWritePermissionsDetected += delegate (string path) {
                this.parentForm.BeginInvoke((System.Windows.Forms.MethodInvoker)delegate {
                    System.Windows.Forms.MessageBox.Show(parentForm, "User is unauthorized to access the following file:" + System.Environment.NewLine + path + System.Environment.NewLine + System.Environment.NewLine + "File(s) will not be extracted!", "Insufficient Write Permissions");
                });
            };

        }

        private void PacketHandler_VoipCallDetected(System.Net.IPAddress ipA, ushort portA, System.Net.IPAddress ipB, ushort portB, string callId, string from, string to) {
            if (this.parentForm.GuiProperties.UseVoipTab)
                if (this.parentForm.VoipCallHandler != null)
                    this.parentForm.VoipCallHandler.PacketHandler_VoipCallDetected(ipA, portA, ipB, portB, callId, from, to);
                //parentForm.VoipCallQueue.Enqueue(new Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, string, string, string>(ipA, portA, ipB, portB, callId, from, to));
        }

        private void PacketHandler_AudioDetected(PacketParser.AudioStream audioStream) {
            if (this.parentForm.GuiProperties.UseVoipTab)
                if (this.parentForm.VoipCallHandler != null)
                    this.parentForm.VoipCallHandler.PacketHandler_AudioDetected(audioStream);
                //parentForm.AudioStreamQueue.Enqueue(audioStream);
                //parentForm.ShowVoipSession(audioStream);//TODO: remove this call
        }

        void packetHandler_HttpTransactionDetected(object sender, PacketParser.Events.HttpClientEventArgs he) {
            if (this.parentForm.GuiProperties.UseBrowsersTab)
                //parentForm.ShowHttpClient(he.HttpClientId, he.Host);
                this.parentForm.HttpClientQueue.Enqueue(he);
        }


        void packetHandler_MessageDetected(object sender, PacketParser.Events.MessageEventArgs me) {
            if (this.parentForm.GuiProperties.UseMessagesTab)
                //parentForm.ShowMessage(me.Protocol, me.SourceHost, me.DestinationHost, me.StartFrameNumber, me.StartTimestamp, me.From, me.To, me.Subject, me.Message, me.MessageEncoding, me.Attributes);
                parentForm.MessageQueue.Enqueue(me);
        }

        void packetHandler_SessionDetected(object sender, PacketParser.Events.SessionEventArgs se) {
            if (this.parentForm.GuiProperties.UseSessionsTab)
                this.parentForm.SessionQueue.Enqueue(se);
                //parentForm.ShowSession(se.Protocol, se.Client, se.Server, se.ClientPort, se.ServerPort, se.Tcp, se.StartFrameNumber, se.StartTimestamp);
        }

        void packetHandler_ParametersDetected(object sender, PacketParser.Events.ParametersEventArgs pe) {
            if (this.parentForm.GuiProperties.UseParametersTab)
                //parentForm.ShowParameters(pe.FrameNumber, pe.SourceHost, pe.DestinationHost, pe.SourcePort, pe.DestinationPort, pe.Parameters, pe.Timestamp, pe.Details);
                this.parentForm.ParametersQueue.Enqueue(pe);
        }

        void packetHandler_NetworkHostDetected(object sender, PacketParser.Events.NetworkHostEventArgs he) {
            if (this.parentForm.GuiProperties.UseHostsTab)
                //parentForm.ShowDetectedHost(he.Host);
                this.parentForm.HostQueue.Enqueue(he.Host);
        }

        void packetHandler_KeywordDetected(object sender, PacketParser.Events.KeywordEventArgs ke) {
            if (this.parentForm.GuiProperties.UseKeywordsTab)
                //parentForm.ShowDetectedKeyword(ke.Frame, ke.KeywordIndex, ke.KeywordLength, ke.SourceHost, ke.DestinationHost, ke.SourcePort, ke.DestinationPort);
                this.parentForm.KeywordQueue.Enqueue(ke);
        }

        void packetHandler_FrameDetected(object sender, PacketParser.Events.FrameEventArgs fe) {
            if(this.parentForm.GuiProperties.UseFramesTab)
                this.parentForm.ShowReceivedFrame(fe.Frame);
        }

        void packetHandler_FileReconstructed(object sender, PacketParser.Events.FileEventArgs fe) {
            if (this.parentForm.GuiProperties.UseFilesTab)
                //parentForm.ShowReconstructedFile(fe.File);
                this.parentForm.FileQueue.Enqueue(fe.File);
        }

        void packetHandler_DnsRecordDetected(object sender, PacketParser.Events.DnsRecordEventArgs de) {
            if (this.parentForm.GuiProperties.UseDnsTab)
                this.parentForm.DnsQueue.Enqueue(de);
            //parentForm.ShowDnsRecord(de.Record, de.DnsServer, de.DnsClient, de.IpPakcet, de.UdpPacket);
        }

        private void AnomalyDetected(object sender, PacketParser.Events.AnomalyEventArgs anomaly) {
            if (this.parentForm.GuiProperties.UseAnomaliesTab)
                this.parentForm.AnomalyQueue.Enqueue(anomaly);
                //parentForm.ShowAnomaly(anomaly.Message, anomaly.Timestamp);
        }
        
        private void CleartextWordsDetected(object sender, PacketParser.Events.CleartextWordsEventArgs cleartextWords) {
            if (this.parentForm.GuiProperties.UseCleartextTab)
                this.parentForm.ShowCleartextWords(cleartextWords.Words, cleartextWords.WordCharCount, cleartextWords.TotalByteCount);
        }
        private void CredentialDetected(object sender, PacketParser.Events.CredentialEventArgs credential) {
            if (this.parentForm.GuiProperties.UseCredentialsTab)
                //parentForm.ShowCredential(credential.Credential);
                this.parentForm.CredentialQueue.Enqueue(credential.Credential);
        }

        private void BufferUsageChanged(object sender, PacketParser.Events.BufferUsageEventArgs bufferUsage) {
            this.parentForm.SnifferBufferToolStripProgressBarNewValue = bufferUsage.BufferUsagePercent;
            //parentForm.SetBufferUsagePercent(bufferUsage.BufferUsagePercent);
        }

        internal void ResetCapturedData(bool removeExtractedFilesFromDisk) {
            if(this.pcapWriter!=null && this.pcapWriter.IsOpen)
                this.pcapWriter.Close();
            this.pcapWriter=null;
            this.packetHandler.ResetCapturedData(removeExtractedFilesFromDisk);

        }

        /*
        internal void SetKeywords(byte[][] keywordList) {
            this.packetHandler.KeywordList=keywordList;
        }*/

        public void StartBackgroundThreads() {
            this.packetHandler.StartBackgroundThreads();
            

        }

        public void AbortBackgroundThreads() {
            this.packetHandler.AbortBackgroundThreads();
        }


        //public void UpdateKeywords(IEnumerable<string> keywords) {
        public void UpdateKeywords(System.Collections.IEnumerable keywords) {
            byte[][] keywordByteArray = PacketParser.Utils.StringManglerUtil.ConvertStringsToByteArrayArray(keywords);
            packetHandler.KeywordList = keywordByteArray;
        }
        

        /// <summary>
        /// Callback method to receive packets from a sniffer
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="packet"></param>
        internal void SnifferPacketReceived(object sender, SharedUtils.Pcap.PacketReceivedEventArgs packet) {
            if(this.packetHandler.TryEnqueueReceivedPacket(sender, packet)) {
                //add frame to pcap file
                if(this.pcapWriter!=null)
                    this.pcapWriter.WriteFrame(new SharedUtils.Pcap.PcapFrame(packet.Timestamp, packet.Data, pcapWriter.DataLinkType));
            }
                
        }


    }
}
