using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser {
    public class AudioStream : IDisposable {

        //http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
        //https://tools.ietf.org/html/rfc2361
        //https://www.codeguru.com/cpp/g-m/multimedia/audio/article.php/c8935/PCM-Audio-and-Wave-Files.htm
        //http://soundfile.sapp.org/doc/WaveFormat/

        private const string FORMAT_PREFIX = "WAVE_FORMAT_";

        /**
         * Common VoIP codecs:
         * 
         * G711_A_64kb 
         * G711_u_64kb 
         * G723 == WAV format # 0x14 || 0x42 || 0x59 || 0x111 || 0x123 (??) Probably none, since RTP uses G723.1 != G723
         * G729 (WAV format only has G.729A, while RTP uses 729B)
         * G726-32 
         * G722 
         * AMR_122k  = 12.2kbit/s GSM 06.60?
         * CLEARMODE 
         */

        public NetworkHost SourceHost { get; }
        public NetworkHost DestinationHost { get; }
        public PacketParser.PacketHandlers.RtpPacketHandler.RtpPayloadType Format { get; }

        public int SampleCount { get { return this.sampleCount; } }
        public FiveTuple FiveTuple { get; }
        public DateTime StartTime { get {
                return this.sampleInfo[0].Timestamp;
            } }
        public DateTime EndTime { get { return this.sampleInfo[this.sampleInfo.Count - 1].Timestamp; } }
        
        public TimeSpan Duration { get {
                return EndTime.Subtract(this.StartTime);
            } }


        private string tempFileName;
        private System.IO.FileStream tempFileStream;
        
        private int sampleCount;
        private List<SampleChunkInfo> sampleInfo;
        private long initialFrameNumber;
        private FileTransfer.FileStreamAssemblerList fileStreamAssemblerList;
        

        private static readonly short[] ALawToLinear16BitPcmTable = {
             -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736,
             -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784,
             -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368,
             -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392,
             -22016,-20992,-24064,-23040,-17920,-16896,-19968,-18944,
             -30208,-29184,-32256,-31232,-26112,-25088,-28160,-27136,
             -11008,-10496,-12032,-11520,-8960, -8448, -9984, -9472,
             -15104,-14592,-16128,-15616,-13056,-12544,-14080,-13568,
             -344,  -328,  -376,  -360,  -280,  -264,  -312,  -296,
             -472,  -456,  -504,  -488,  -408,  -392,  -440,  -424,
             -88,   -72,   -120,  -104,  -24,   -8,    -56,   -40,
             -216,  -200,  -248,  -232,  -152,  -136,  -184,  -168,
             -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
             -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696,
             -688,  -656,  -752,  -720,  -560,  -528,  -624,  -592,
             -944,  -912,  -1008, -976,  -816,  -784,  -880,  -848,
              5504,  5248,  6016,  5760,  4480,  4224,  4992,  4736,
              7552,  7296,  8064,  7808,  6528,  6272,  7040,  6784,
              2752,  2624,  3008,  2880,  2240,  2112,  2496,  2368,
              3776,  3648,  4032,  3904,  3264,  3136,  3520,  3392,
              22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944,
              30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136,
              11008, 10496, 12032, 11520, 8960,  8448,  9984,  9472,
              15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568,
              344,   328,   376,   360,   280,   264,   312,   296,
              472,   456,   504,   488,   408,   392,   440,   424,
              88,    72,   120,   104,    24,     8,    56,    40,
              216,   200,   248,   232,   152,   136,   184,   168,
              1376,  1312,  1504,  1440,  1120,  1056,  1248,  1184,
              1888,  1824,  2016,  1952,  1632,  1568,  1760,  1696,
              688,   656,   752,   720,   560,   528,   624,   592,
              944,   912,  1008,   976,   816,   784,   880,   848
        };

        private static readonly short[] MuLawToLinear16BitPcmTable = {
             -32124,-31100,-30076,-29052,-28028,-27004,-25980,-24956,
             -23932,-22908,-21884,-20860,-19836,-18812,-17788,-16764,
             -15996,-15484,-14972,-14460,-13948,-13436,-12924,-12412,
             -11900,-11388,-10876,-10364, -9852, -9340, -8828, -8316,
              -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
              -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
              -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
              -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
              -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
              -1372, -1308, -1244, -1180, -1116, -1052,  -988,  -924,
               -876,  -844,  -812,  -780,  -748,  -716,  -684,  -652,
               -620,  -588,  -556,  -524,  -492,  -460,  -428,  -396,
               -372,  -356,  -340,  -324,  -308,  -292,  -276,  -260,
               -244,  -228,  -212,  -196,  -180,  -164,  -148,  -132,
               -120,  -112,  -104,   -96,   -88,   -80,   -72,   -64,
                -56,   -48,   -40,   -32,   -24,   -16,    -8,     -1,
              32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
              23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
              15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
              11900, 11388, 10876, 10364,  9852,  9340,  8828,  8316,
               7932,  7676,  7420,  7164,  6908,  6652,  6396,  6140,
               5884,  5628,  5372,  5116,  4860,  4604,  4348,  4092,
               3900,  3772,  3644,  3516,  3388,  3260,  3132,  3004,
               2876,  2748,  2620,  2492,  2364,  2236,  2108,  1980,
               1884,  1820,  1756,  1692,  1628,  1564,  1500,  1436,
               1372,  1308,  1244,  1180,  1116,  1052,   988,   924,
                876,   844,   812,   780,   748,   716,   684,   652,
                620,   588,   556,   524,   492,   460,   428,   396,
                372,   356,   340,   324,   308,   292,   276,   260,
                244,   228,   212,   196,   180,   164,   148,   132,
                120,   112,   104,    96,    88,    80,    72,    64,
                 56,    48,    40,    32,    24,    16,     8,     0
        };


        /*
        public AudioStream(NetworkHost sourceHost, NetworkHost destinationHost, AudioFormat format,
            FileTransfer.FileStreamAssemblerList fileStreamAssemblerList, FiveTuple fiveTuple, long initialFrameNumber) {
            */
        public AudioStream(NetworkHost sourceHost, NetworkHost destinationHost, PacketParser.PacketHandlers.RtpPacketHandler.RtpPayloadType format, FileTransfer.FileStreamAssemblerList fileStreamAssemblerList, FiveTuple fiveTuple, long initialFrameNumber) {
            this.SourceHost = sourceHost;
            this.DestinationHost = destinationHost;
            this.Format = format;
            //this.Assembler = assembler;
            this.fileStreamAssemblerList = fileStreamAssemblerList;
            this.FiveTuple = fiveTuple;
            this.initialFrameNumber = initialFrameNumber;
            this.sampleCount = 0;
            //The GetTempFileName method will raise an IOException if it is used to create more than 65535 files without deleting previous temporary files.
            //The GetTempFileName method will raise an IOException if no unique temporary file name is available.To resolve this error, delete all unneeded temporary files.
            this.tempFileName = System.IO.Path.GetTempFileName();
            FileTransfer.FileStreamAssemblerList.TempFileHandlers.Add(this);

            this.tempFileStream = new System.IO.FileStream(tempFileName, System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite, System.IO.FileShare.Read, 262144);
            this.sampleInfo = new List<SampleChunkInfo>();
        }

        public void AddSamples(byte[] data, uint sampleTick, DateTime timestamp, uint syncSourceID) {
            this.sampleInfo.Add(new SampleChunkInfo(sampleTick, timestamp, tempFileStream.Position, data.Length, syncSourceID));
            tempFileStream.Write(data, 0, data.Length);
            //tempFS.Flush();
            this.sampleCount++;

        }



        private SampleChunkInfo GetMinJitterTimeReference(uint sampleRate) {
            DateTime startTime = this.sampleInfo[0].Timestamp;
            uint startSampleTick = this.sampleInfo[0].SampleTick;
            double minJitter = 100;
            SampleChunkInfo bestTuple = null;
            uint firstSyncSourceId = this.sampleInfo[0].SyncSourceID;
            foreach(SampleChunkInfo tuple in this.sampleInfo) {
                if (tuple.SyncSourceID != firstSyncSourceId)
                    break;
                double seconds = tuple.Timestamp.Subtract(startTime).TotalSeconds;
                uint sampleTicks = tuple.SampleTick - startSampleTick;
                //avoid using the first chunk
                if (sampleTicks > 0 && seconds * sampleRate - sampleTicks < minJitter) {
                    minJitter = seconds * sampleRate - sampleTicks;
                    bestTuple = tuple;
                }
            }
            return bestTuple;
        }


        public FileTransfer.FileStreamAssembler MergeAsStereoWavAssembler(AudioStream other) {

            uint sampleRate = 8000;

            FileTransfer.WavFileAssembler mergedAssembler = new FileTransfer.WavFileAssembler("MergedAudioStreams-" + FiveTuple.GetHashCode() + ".wav", this.fileStreamAssemblerList, this.FiveTuple, FileTransfer.FileStreamTypes.RTP, this.initialFrameNumber, this.StartTime, sampleRate);
            //figure out if sample rates match with sampleTicks etc.
            //double thisSampleRateSkew = this.GetSampleTicksPerSecond() / sampleRate;
            //double otherSampleRateSkew = other.GetSampleTicksPerSecond() / sampleRate;

            //if (thisSampleRateSkew > 0.9 && thisSampleRateSkew < 1.11 && otherSampleRateSkew > 0.9 && otherSampleRateSkew < 1.11) {
            //figure out the correct start time and lock that to a sampleTick
            double nanosecondHundredsPerSample = 10000000.0 / sampleRate;//8000Hz => 1250

            SampleChunkInfo thisTimeReference = this.GetMinJitterTimeReference(sampleRate);
            TimeSpan thisTicksReferenceOffset = new TimeSpan((long)(nanosecondHundredsPerSample * ((int)thisTimeReference.SampleTick - this.sampleInfo[0].SampleTick)));
            DateTime thisFirstSampleTimestamp = thisTimeReference.Timestamp.Subtract(thisTicksReferenceOffset);

            SampleChunkInfo otherTimeReference = other.GetMinJitterTimeReference(sampleRate);
            TimeSpan otherTicksReferenceOffset = new TimeSpan((long)(nanosecondHundredsPerSample * ((int)otherTimeReference.SampleTick - other.sampleInfo[0].SampleTick)));
            DateTime otherFirstSampleTimestamp = otherTimeReference.Timestamp.Subtract(otherTicksReferenceOffset);

            long thisSampleTicksOffset, otherSampleTicksOffset;
            if (thisFirstSampleTimestamp < otherFirstSampleTimestamp) {
                thisSampleTicksOffset = this.sampleInfo[0].SampleTick;
                otherSampleTicksOffset = otherTimeReference.SampleTick - (long)(otherTimeReference.Timestamp.Subtract(thisFirstSampleTimestamp).Ticks / nanosecondHundredsPerSample);
            }
            else {
                thisSampleTicksOffset = thisTimeReference.SampleTick - (long)(thisTimeReference.Timestamp.Subtract(otherFirstSampleTimestamp).Ticks / nanosecondHundredsPerSample);
                otherSampleTicksOffset = other.sampleInfo[0].SampleTick;
            }

            var thisLastTuple = this.sampleInfo[this.sampleInfo.Count - 1];
            var otherLastTuple = other.sampleInfo[other.sampleInfo.Count - 1];
            
            //uint metaDataLength = 0;
            mergedAssembler.TryActivate();



            //nSamples might be incorrect here
            Pcm16BitSampleStream thisStream = new Pcm16BitSampleStream(this, thisSampleTicksOffset, true);
            Pcm16BitSampleStream otherStream = new Pcm16BitSampleStream(other, otherSampleTicksOffset, true);

            //uint nSamples = (uint)Math.Max(thisLastTuple.SampleTick + thisLastTuple.DataLength - thisSampleTicksOffset, otherLastTuple.SampleTick + otherLastTuple.DataLength - otherSampleTicksOffset);
            uint nSamples = mergedAssembler.CountSamplesInStreams(thisStream, otherStream);
            //reset positions
            thisStream.Position = 0;
            otherStream.Position = 0;

            mergedAssembler.WriteSampleStreamToFile(nSamples, thisStream, otherStream);

            //mergedAssembler.FinishAssembling();
            return mergedAssembler;
        }

        public FileTransfer.FileStreamAssembler AssembleAsWavFile() {
            if (this.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G711_PCM_A)
                return this.AssembleAsWavFile(ALawToLinear16BitPcmTable);
            else if (this.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G711_PCM_U)
                return this.AssembleAsWavFile(MuLawToLinear16BitPcmTable);
            else {
                return this.AssembleAsWavFileNative();
            }
        }



        public FileTransfer.FileStreamAssembler AssembleAsWavFile(short[] decompressionTable, bool insertSilenceOnMissingData = false) {

            uint sampleRate = 8000;


            byte bitsPerSampleIn = 8;
            uint nSamples = (uint)((this.tempFileStream.Length*8)/ bitsPerSampleIn);
            FileTransfer.WavFileAssembler assembler = new FileTransfer.WavFileAssembler("AudioStream-" + this.FiveTuple.GetHashCode().ToString() + ".wav", this.fileStreamAssemblerList, this.FiveTuple, FileTransfer.FileStreamTypes.RTP, this.initialFrameNumber, this.StartTime, sampleRate);
            assembler.TryActivate();
            Pcm16BitSampleStream stream = new Pcm16BitSampleStream(this, this.sampleInfo[0].SampleTick, insertSilenceOnMissingData);
            assembler.WriteSampleStreamToFile(nSamples, stream);

            //assembler.FinishAssembling();
            return assembler;
            
        }

        public FileTransfer.FileStreamAssembler AssembleAsWavFileNative() {
            uint sampleRate = 8000;
            
            byte bitsPerSample = 8;

            FileTransfer.WavFileAssembler.AudioFormat outFormat;

            if(this.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G722) {
                //only AU format handles G722
                FileTransfer.AuFileAssembler auAssembler = new FileTransfer.AuFileAssembler("AudioStream-" + this.FiveTuple.GetHashCode().ToString() + "-" + this.Format.ToString() + ".au", this.fileStreamAssemblerList, this.FiveTuple, FileTransfer.FileStreamTypes.RTP, this.initialFrameNumber, this.StartTime, FileTransfer.AuFileAssembler.Encoding.G722, sampleRate);
                if(auAssembler.TryActivate()) {
                    auAssembler.AssembleAsWavFileNative(this.tempFileStream);
                }
                return auAssembler;
            }
            else if (this.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G729) {
                bitsPerSample = 1;
                outFormat = FileTransfer.WavFileAssembler.AudioFormat.WAVE_FORMAT_G729;
            }
            else if (this.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G711_PCM_A) {
                outFormat = FileTransfer.WavFileAssembler.AudioFormat.WAVE_FORMAT_ALAW;
            }
            else if (this.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G711_PCM_U) {
                outFormat = FileTransfer.WavFileAssembler.AudioFormat.WAVE_FORMAT_MULAW;
            }
            else
                throw new NotImplementedException("WAV extraction of " + this.Format.ToString() + " format is not implemented");

            uint nSamples = (uint)((this.tempFileStream.Length * 8) / bitsPerSample);
            //uint metaDataLength = 0;


            FileTransfer.WavFileAssembler assembler = new FileTransfer.WavFileAssembler("AudioStream-" + this.FiveTuple.GetHashCode().ToString() + "-" + this.Format.ToString() + ".wav", this.fileStreamAssemblerList, this.FiveTuple, FileTransfer.FileStreamTypes.RTP, this.initialFrameNumber, this.StartTime, sampleRate);
            if(assembler.TryActivate())
                assembler.AssembleAsWavFileNative(this.tempFileStream, outFormat);

            return assembler;
        }

        public void Dispose() {
            try {
                if (this.tempFileStream != null)
                {
                    this.tempFileStream.Close();
                }
                this.tempFileStream = null;
            }
            catch { }
            try {
                if (this.tempFileStream != null)
                    this.tempFileStream.Dispose();
            }
            catch { }
            if(this.tempFileName != null)
            {
                try
                {
                    File.Delete(this.tempFileName);
                }
                catch { }
            }
            this.tempFileStream = null;
        }

        //<uint, DateTime, long, int, uint>
        internal class SampleChunkInfo {

            internal uint SampleTick { get; }//SampleTick
            internal DateTime Timestamp { get; }//Timestamp
            internal long TempFsPosition { get; }//TempFsPosition
            internal int DataLength { get; }//DataLength
            internal uint SyncSourceID { get; }//SyncSourceID

            //(sampleTick, timestamp, tempFS.Position, data.Length, syncSourceID));
            internal SampleChunkInfo(uint sampleTick, DateTime timestamp, long tempFsPosition, int dataLength, uint syncSourceID) {
                this.SampleTick = sampleTick;
                this.Timestamp = timestamp;
                this.TempFsPosition = tempFsPosition;
                this.DataLength = dataLength;
                this.SyncSourceID = syncSourceID;
            }
        }

        internal class Pcm16BitSampleStream : System.IO.Stream {

            private AudioStream audioStream;
            private long firstSampleTick;
            private MemoryStream pcm16Stream;
            private long writePosition, readPosition;
            private int sampleChunkIndex;
            private short[] decompressionTable;
            private uint? currentSyncSourceID;
            private bool insertSilenceOnMissingSamples;


            public override bool CanRead {
                get {
                    return true;
                }
            }

            public override bool CanSeek {
                get {
                    return false;
                }
            }

            public override bool CanWrite {
                get {
                    return false;
                }
            }

            public override long Length {
                get {
                    return this.pcm16Stream.Length;
                }
            }

            public override long Position {
                get {
                    return this.pcm16Stream.Position;
                }

                set {
                    if(value == 0) {
                        this.writePosition = 0;
                        this.readPosition = 0;
                    }
                    else
                        throw new NotImplementedException();
                }
            }


            internal Pcm16BitSampleStream(AudioStream audioStream, long firstSampleTick, bool insertSilenceOnMissingSamples) {
                if (audioStream.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G711_PCM_A)
                    this.decompressionTable = AudioStream.ALawToLinear16BitPcmTable;
                else if (audioStream.Format == PacketHandlers.RtpPacketHandler.RtpPayloadType.G711_PCM_U)
                    this.decompressionTable = AudioStream.MuLawToLinear16BitPcmTable;
                else
                    throw new NotSupportedException("Only u-Law and A-Law formats are supported");

                this.audioStream = audioStream;
                this.firstSampleTick = firstSampleTick;
                this.insertSilenceOnMissingSamples = insertSilenceOnMissingSamples;

                this.pcm16Stream = new MemoryStream();
            }

            public override void Flush() {
                throw new NotImplementedException();
            }

            public override int Read(byte[] buffer, int offset, int count) {
                int bytesRead;
                lock (this.pcm16Stream) {
                    lock (this.audioStream.tempFileStream) {
                        while (this.writePosition < this.readPosition + count && this.sampleChunkIndex < this.audioStream.sampleInfo.Count) {
                            
                                
                            this.pcm16Stream.Position = writePosition;
                            SampleChunkInfo sampleInfo = this.audioStream.sampleInfo[this.sampleChunkIndex];
                            if (this.currentSyncSourceID == null)
                                this.currentSyncSourceID = sampleInfo.SyncSourceID;
                            else if(this.currentSyncSourceID.Value != sampleInfo.SyncSourceID) {
                                //new source
                                this.currentSyncSourceID = sampleInfo.SyncSourceID;
                                this.firstSampleTick = sampleInfo.SampleTick - this.writePosition / 2;
                                if (this.firstSampleTick < 0) {
                                    SharedUtils.Logger.Log("Changing VoIP first sample tick from " + this.firstSampleTick + " to 0", SharedUtils.Logger.EventLogEntryType.Warning);
                                    this.firstSampleTick = 0;
                                }
                            }

                            this.audioStream.tempFileStream.Position = sampleInfo.TempFsPosition;
                            byte[] inputBuffer = new byte[sampleInfo.DataLength];
                            int inputBytesRead = this.audioStream.tempFileStream.Read(inputBuffer, 0, inputBuffer.Length);
                            if (this.insertSilenceOnMissingSamples) {
                                while (sampleInfo.SampleTick > firstSampleTick + this.writePosition / 2) {
                                    byte[] firstSample = Utils.ByteConverter.ToByteArray((ushort)this.decompressionTable[inputBuffer[0]], true);
                                    this.pcm16Stream.Write(firstSample, 0, 2);//write first value of the input stream
                                    this.writePosition += 2;
                                }
                            }
                            //byte[] pcm16 = new byte[inputBytesRead * 2];
                            for (int i = 0; i < inputBytesRead; i++) {
                                //byte[] b2 = Utils.ByteConverter.ToByteArray((ushort)decompressionTable[inputBuffer[i]], true);
                                //pcm16[2 * i] = b2[0];
                                //pcm16[2 * i + 1] = b2[1];
                                this.pcm16Stream.Write(Utils.ByteConverter.ToByteArray((ushort)decompressionTable[inputBuffer[i]], true), 0, 2);
                                this.writePosition += 2;
                            }
                            //this.pcm16Stream.Write(pcm16, 0, pcm16.Length);
                            //this.writePosition += pcm16.Length;

                            this.sampleChunkIndex++;
                        }
                    }
                    this.pcm16Stream.Position = this.readPosition;
                    bytesRead = this.pcm16Stream.Read(buffer, offset, count);
                    this.readPosition += bytesRead;
                }
                return bytesRead;
            }

            public override long Seek(long offset, SeekOrigin origin) {
                throw new NotImplementedException();
            }

            public override void SetLength(long value) {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count) {
                throw new NotImplementedException();
            }
        }
    }
}
