using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.FileTransfer {
    public class WavFileAssembler : FileStreamAssembler {

        //http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
        //https://tools.ietf.org/html/rfc2361
        public enum AudioFormat : ushort {
            WAVE_FORMAT_PCM = 1,
            WAVE_FORMAT_IEEE_FLOAT = 3,
            WAVE_FORMAT_ALAW = 6,//ITU-T G.711 PCM A-Law audio 64 kbit/s
            WAVE_FORMAT_MULAW = 7,//ITU-T G.711 PCM µ-Law audio 64 kbit/s
            //WAVE_FORMAT_DVI_ADPCM = 0x11,//Intel's DVI ADPCM
            WAVE_FORMAT_GSM610 = 0x31,//European GSM Full Rate audio 13 kbit/s (GSM 06.10)
            WAVE_FORMAT_G729 = 0x83,//WAV uses G.720, but RTP uses ITU-T G.729 or G.729a audio 8 kbit/s (Annex B is implied unless the annexb=no parameter is used)
            WAVE_FORMAT_EXTENSIBLE = 0xfffe
        }

        private uint sampleRate;


        public WavFileAssembler(string wavFilename, FileStreamAssemblerList fileStreamAssemblerList, FiveTuple fiveTuple, FileStreamTypes fileStreamType, long initialFrameNumber, DateTime startTime, uint sampleRate = 8000) :
            base(fileStreamAssemblerList, fiveTuple, true, fileStreamType, wavFilename, "/", fileStreamType.ToString() + " " + fiveTuple.ToString(), initialFrameNumber, startTime) {
            if(fileStreamType == FileStreamTypes.RTP) {
                this.FileContentLength = -1;
                this.FileSegmentRemainingBytes = -1;
                //this.fileStreamAssemblerList.Add(assembler);
            }
            this.sampleRate = sampleRate;
        }

        private void WriteWavHeader(ref uint wc, AudioFormat audioFormat, byte nChannels, byte bitsPerSampleOut, uint nSamples) {
            uint metaDataLength = 0;

            //Write WAV header http://soundfile.sapp.org/doc/WaveFormat/
            this.AddData(System.Text.ASCIIEncoding.ASCII.GetBytes("RIFF"), wc++);
            if (audioFormat == AudioFormat.WAVE_FORMAT_PCM)
                this.AddData(Utils.ByteConverter.ToByteArray(nSamples * nChannels * bitsPerSampleOut / 8 + 36 + metaDataLength, true), wc++);//ChunkSize = This is the size of the rest of the chunk following this number.This is the size of the entire file in bytes minus 8 bytes for the two fields not included in this count: ChunkID and ChunkSize.
            else if (audioFormat == AudioFormat.WAVE_FORMAT_ALAW || audioFormat == AudioFormat.WAVE_FORMAT_MULAW)
                this.AddData(Utils.ByteConverter.ToByteArray(nSamples + 50 + metaDataLength, true), wc++);//ChunkSize = This is the size of the rest of the chunk following this number.This is the size of the entire file in bytes minus 8 bytes for the two fields not included in this count: ChunkID and ChunkSize.
            else if (audioFormat == AudioFormat.WAVE_FORMAT_G729)
                this.AddData(Utils.ByteConverter.ToByteArray(nSamples * 8 + 50 + metaDataLength, true), wc++);//ChunkSize = This is the size of the rest of the chunk following this number.This is the size of the entire file in bytes minus 8 bytes for the two fields not included in this count: ChunkID and ChunkSize.
            else
                throw new NotSupportedException("Only PCM, A-Law, u-Law and G.729 supported!");
            this.AddData(System.Text.ASCIIEncoding.ASCII.GetBytes("WAVE"), wc++);

            //==fmt chunk (26 bytes)==
            this.AddData(System.Text.ASCIIEncoding.ASCII.GetBytes("fmt "), wc++);
            if (audioFormat == AudioFormat.WAVE_FORMAT_PCM)
                this.AddData(new byte[] { 0x10, 0, 0, 0 }, wc++);//Subchunk1Size (0x10 = PCM with no extra) Chunk size: 16, 18 or 40 according to http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
            else if (audioFormat == AudioFormat.WAVE_FORMAT_ALAW || audioFormat == AudioFormat.WAVE_FORMAT_MULAW || audioFormat == AudioFormat.WAVE_FORMAT_G729)
                this.AddData(new byte[] { 0x12, 0, 0, 0 }, wc++);//Subchunk1Size (0x10 = PCM with no extra) Chunk size: 16, 18 or 40 according to http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
            this.AddData(Utils.ByteConverter.ToByteArray((ushort)audioFormat, true), wc++);//AudioFormat
            this.AddData(new byte[] { nChannels, 0 }, wc++);//NumChannels (1 = Mono)
            this.AddData(Utils.ByteConverter.ToByteArray(sampleRate, true), wc++);//SampleRate
            this.AddData(Utils.ByteConverter.ToByteArray((sampleRate * nChannels * bitsPerSampleOut) / 8, true), wc++);//ByteRate == SampleRate * NumChannels * BitsPerSample/8
            this.AddData(Utils.ByteConverter.ToByteArray((ushort)(nChannels * bitsPerSampleOut / 8), true), wc++);//BlockAlign
            this.AddData(new byte[] { bitsPerSampleOut, 0 }, wc++);//BitsPerSample
            if (audioFormat == AudioFormat.WAVE_FORMAT_ALAW || audioFormat == AudioFormat.WAVE_FORMAT_MULAW || audioFormat == AudioFormat.WAVE_FORMAT_G729) {
                this.AddData(new byte[] { 0, 0 }, wc++);//cbSize 	(Size of the extension (0 or 22) NOT IN PCM!

                //==fact chunk (12 bytes)== http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
                this.AddData(System.Text.ASCIIEncoding.ASCII.GetBytes("fact"), wc++);
                this.AddData(new byte[] { 4, 0, 0, 0 }, wc++);//Chunk size: minimum 4
                this.AddData(Utils.ByteConverter.ToByteArray(nSamples, true), wc++);
            }

            //==DATA (8 bytes + samples)==
            this.AddData(System.Text.ASCIIEncoding.ASCII.GetBytes("data"), wc++);//Subchunk2ID
            this.AddData(Utils.ByteConverter.ToByteArray(nSamples * nChannels * bitsPerSampleOut / 8, true), wc++);//Subchunk2Size == NumSamples * NumChannels * BitsPerSample/8

        }

        public void AssembleAsWavFileNative(System.IO.FileStream rawSamplesFileStream, AudioFormat format) {
            uint wc = 0;

            byte nChannels = 1;//mono

            byte bitsPerSample = 8;
            if (format == AudioFormat.WAVE_FORMAT_G729)
                bitsPerSample = 1;

            uint nSamples = (uint)((rawSamplesFileStream.Length * 8) / bitsPerSample);
            uint metaDataLength = 0;
            //assembler.TryActivate();
            //Write WAV header http://soundfile.sapp.org/doc/WaveFormat/
            this.WriteWavHeader(ref wc, format, nChannels, bitsPerSample, nSamples);

            //write WAV data
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

        public uint CountSamplesInStreams(System.IO.Stream pcm16BitSamplesChannelA, System.IO.Stream pcm16BitSamplesChannelB) {
            uint nSamples = 0;
            byte[] thisBuf = new byte[4096];
            byte[] otherBuf = new byte[4096];
            while (true) {
                int thisCount = pcm16BitSamplesChannelA.Read(thisBuf, 0, thisBuf.Length);
                int otherCount = pcm16BitSamplesChannelB.Read(otherBuf, 0, otherBuf.Length);
                if (thisCount < 1 && otherCount < 1)
                    break;
                nSamples += (uint)Math.Max(thisCount, otherCount)/2;//16 bit samples => *0.5
            }
            return nSamples;
        }

        public void WriteSampleStreamToFile(uint nSamples, System.IO.Stream pcm16BitSamplesChannelA, System.IO.Stream pcm16BitSamplesChannelB) {
            uint wc = 0;
            this.WriteWavHeader(ref wc, AudioFormat.WAVE_FORMAT_PCM, 2, 16, nSamples);
            uint writtenSamples = 0;
            while (true) {
                byte[] thisBuf = new byte[4096];
                byte[] otherBuf = new byte[4096];
                int thisCount = pcm16BitSamplesChannelA.Read(thisBuf, 0, thisBuf.Length);
                int otherCount = pcm16BitSamplesChannelB.Read(otherBuf, 0, otherBuf.Length);
                if (thisCount < 1 && otherCount < 1)
                    break;
                byte[] mergedBuf = new byte[Math.Max(thisCount, otherCount) * 2];
                for (int i = 0; i < thisCount - 1; i += 2) {
                    mergedBuf[i * 2 + 0] = thisBuf[i];
                    mergedBuf[i * 2 + 1] = thisBuf[i + 1];
                }
                for (int i = 0; i < otherCount - 1; i += 2) {
                    mergedBuf[i * 2 + 2] = otherBuf[i];
                    mergedBuf[i * 2 + 3] = otherBuf[i + 1];
                }
                this.AddData(mergedBuf, wc++);
                writtenSamples += (uint)mergedBuf.Length;
            }
        }

        public void WriteSampleStreamToFile(uint nSamples, System.IO.Stream pcm16BitSamplesChannelA) {
            uint wc = 0;
            if (pcm16BitSamplesChannelA == null)
                throw new ArgumentNullException("Stream cannot be null");
            this.WriteWavHeader(ref wc, AudioFormat.WAVE_FORMAT_PCM, 1, 16, nSamples);
            while (true) {
                byte[] buf = new byte[4096];
                int count = pcm16BitSamplesChannelA.Read(buf, 0, buf.Length);
                if (count < 1)
                    break;
                this.AddData(buf.Take(count).ToArray(), wc++);
            }
        }
    }
}
