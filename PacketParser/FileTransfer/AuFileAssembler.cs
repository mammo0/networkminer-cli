using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.FileTransfer {
    public class AuFileAssembler : FileStreamAssembler {

        private uint sampleRate;
        private uint wc = 0;

        public enum Encoding : uint {
            G711_ULAW = 1,
            PCM_8BIT = 2,
            PCM_16BIT = 3,
            //PCM_24BIT = 4,
            //PCM_32BIT = 5,
            //IEEE_FLOAT_32BIT = 6,
            //IEEE_FLOAT_64BIT = 7,
            //FRAGMENTED_SAMPLE_DATA = 8,
            //DSP_PROGRAM = 9,
            //FIXED_POINT_8BIT = 10,
            //FIXED_POINT_16BIT = 11,
            //FIXED_POINT_24BIT = 12,
            //FIXED_POINT_32BIT = 13,
            //18 = 16 - bit linear with emphasis
            //19 = 16 - bit linear compressed
            //20 = 16 - bit linear with emphasis and compression
            //21 = Music kit DSP commands
            //23 = 4 - bit compressed using the ITU-T G.721 ADPCM voice data encoding scheme
            G722 = 24,//ITU-T G.722 SB-ADPCM
            //25 = ITU-T G.723 3-bit ADPCM
            //26 = ITU-T G.723 5-bit ADPCM
            G711_ALAW = 27//8-bit G.711 A-law
        };

        public Encoding AuEncoding { get; }

        public AuFileAssembler(string auFilename, FileStreamAssemblerList fileStreamAssemblerList, FiveTuple fiveTuple, FileStreamTypes fileStreamType, long initialFrameNumber, DateTime startTime, Encoding auEncoding, uint sampleRate = 8000) :
            base(fileStreamAssemblerList, fiveTuple, true, fileStreamType, auFilename, "/", fileStreamType.ToString() + " " + fiveTuple.ToString(), initialFrameNumber, startTime) {
            this.sampleRate = sampleRate;
            this.AuEncoding = auEncoding;
            //unknown file size
            this.FileContentLength = -1;
            this.FileSegmentRemainingBytes = -1;
        }

        internal override bool TryActivate() {
            
            if (base.TryActivate()) {
                //write Au header : https://en.wikipedia.org/wiki/Au_file_format
                base.AddData(Utils.ByteConverter.ToByteArray((uint)0x2e736e64, false), wc++);//0x2e736e64 = .snd
                base.AddData(Utils.ByteConverter.ToByteArray((uint)24, false), wc++);//data offset. The minimum valid number is 24 (decimal)
                base.AddData(Utils.ByteConverter.ToByteArray((uint)0xffffffff, false), wc++);//data size in bytes. If unknown, the value 0xffffffff should be used.
                base.AddData(Utils.ByteConverter.ToByteArray((uint)this.AuEncoding, false), wc++);//Data encoding format: 
                base.AddData(Utils.ByteConverter.ToByteArray(this.sampleRate, false), wc++);//sample rate
                base.AddData(Utils.ByteConverter.ToByteArray((uint)1, false), wc++);//channels

                return true;
            }
            else
                return false;
        }

        public void AssembleAsWavFileNative(System.IO.FileStream rawSamplesFileStream) {

            lock (rawSamplesFileStream) {
                rawSamplesFileStream.Position = 0;

                while (true) {
                    byte[] buf = new byte[4096];
                    int count = rawSamplesFileStream.Read(buf, 0, buf.Length);
                    if (count < 1)
                        break;
                    if (count == buf.Length)
                        this.AddData(buf, wc++);
                    else
                        this.AddData(buf.Take(count).ToArray(), wc++);
                }
            }
        }

    }


}
