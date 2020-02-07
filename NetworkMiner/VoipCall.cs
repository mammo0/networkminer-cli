using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Schema;

using System.Windows.Forms;
using System.Reflection;

namespace NetworkMiner {

    [Obfuscation(Feature = "internalization", Exclude = true)]
    public class VoipCall : System.Xml.Serialization.IXmlSerializable {
        private const string FORMAT_PREFIX = "WAVE_FORMAT_";
        private Func<DateTime, string> toCustomTimeZoneStringFunction;

        public DateTime Start { get; }
        public DateTime End { get; }
        public string CallId { get; }
        public string From { get; }
        public string To { get; }
        public PacketParser.NetworkHost SourceHost { get; }
        public PacketParser.NetworkHost DestinationkHost { get; }
        public PacketParser.PacketHandlers.RtpPacketHandler.RtpPayloadType Encoding { get; }
        public string EncodingString { get; }

        public string WavFilePath {
            get {
                if (this.reconstructedFile == null)
                    return null;
                else {
                    return reconstructedFile.FilePath;
                }
            }
        }

        private PacketParser.FileTransfer.ReconstructedFile reconstructedFile;

        private VoipCall() {
            //for XML serialization
        }

        public VoipCall(List<PacketParser.AudioStream> audioStreamList, PacketParser.FileTransfer.FileStreamAssembler wavAssembler, string callId, string from, string to, Func<DateTime, string> toCustomTimeZoneStringFunction) : base () {
            this.toCustomTimeZoneStringFunction = toCustomTimeZoneStringFunction;
            this.reconstructedFile = null;
            //audioStream.Assembler.FileReconstructed += this.Assembler_FileReconstructed;
            wavAssembler.FileReconstructed += this.OnWavFileReconstructed;

            this.Start = DateTime.MaxValue;
            this.End = DateTime.MinValue;
            foreach (PacketParser.AudioStream stream in audioStreamList) {
                if (stream.StartTime < this.Start)
                    this.Start = stream.StartTime;
                if (stream.EndTime > this.End)
                    this.End = stream.EndTime;
            }
            this.CallId = callId;
            this.From = from;
            this.To = to;



            this.SourceHost = audioStreamList[0].SourceHost;
            this.DestinationkHost = audioStreamList[0].DestinationHost;
            this.Encoding = audioStreamList[0].Format;
            this.EncodingString = this.Encoding.ToString();
            if (this.EncodingString.StartsWith(FORMAT_PREFIX))
                this.EncodingString = this.EncodingString.Substring(FORMAT_PREFIX.Length);


        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            writer.WriteElementString("From", this.From);
            writer.WriteElementString("To", this.To);
            writer.WriteElementString("Start", this.toCustomTimeZoneStringFunction(this.Start));
            writer.WriteElementString("Duration", this.End.Subtract(this.Start).ToString());
            writer.WriteElementString("Encoding", this.EncodingString);
            writer.WriteElementString("Call-ID", this.CallId);
            writer.WriteElementString("Source", this.SourceHost.ToString());
            writer.WriteElementString("Destination", this.DestinationkHost.ToString());
            writer.WriteElementString("Path", this.WavFilePath);

        }

        private void OnWavFileReconstructed(string extendedFileId, PacketParser.FileTransfer.ReconstructedFile file) {
            this.reconstructedFile = file;
            //this.player = new System.Media.SoundPlayer(this.reconstructedFile.FilePath);
        }

        internal VoipCallDataGridViewRow CreateVoipCallDataGridViewRow() {
            return new VoipCallDataGridViewRow(this);
        }

        internal class VoipCallDataGridViewRow : System.Windows.Forms.DataGridViewRow {
            private System.Media.SoundPlayer player = null;

            public VoipCall VoipCall { get; }

            internal VoipCallDataGridViewRow(VoipCall voipCall) {
                this.VoipCall = voipCall;

                DataGridViewImageCell playCell = new DataGridViewImageCell() {
                    Value = NetworkMiner.Properties.Resources.PlayHS,
                    //ToolTipText = "Play"
                };
                playCell.Style.BackColor = System.Drawing.SystemColors.ButtonFace;
                playCell.Style.SelectionBackColor = playCell.Style.BackColor;
                playCell.AdjustCellBorderStyle(new DataGridViewAdvancedBorderStyle() { All = DataGridViewAdvancedCellBorderStyle.Single }, new DataGridViewAdvancedBorderStyle(), true, true, false, false);

                DataGridViewImageCell stopCell = new DataGridViewImageCell() {
                    Value = NetworkMiner.Properties.Resources.StopHS,
                    //ToolTipText = "Stop",
                };
                stopCell.Style.BackColor = System.Drawing.SystemColors.ButtonFace;
                stopCell.Style.SelectionBackColor = stopCell.Style.BackColor;

                base.Cells.Add(playCell);
                base.Cells.Add(stopCell);
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.From });
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.To });
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.toCustomTimeZoneStringFunction(voipCall.Start) });
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.End.Subtract(voipCall.Start).ToString() });
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.EncodingString });
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.CallId });
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.SourceHost.ToString() });
                base.Cells.Add(new DataGridViewTextBoxCell { Value = voipCall.DestinationkHost.ToString() });
                base.Cells.Add(new DataGridViewButtonCell { Value = "Save .wav" });
            }

            internal void Play() {
                if (this.VoipCall.reconstructedFile != null) {
                    if(this.player == null)
                        this.player = new System.Media.SoundPlayer(this.VoipCall.reconstructedFile.FilePath);
                    this.player.Play();
                }

            }

            internal void Stop() {
                if (this.player != null)
                    this.player.Stop();
            }
        }
    }
}
