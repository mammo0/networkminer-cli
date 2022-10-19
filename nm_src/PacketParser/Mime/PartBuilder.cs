using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Mime {
    static class PartBuilder {

        public static IEnumerable<MultipartPart> GetParts(byte[] mimeMultipartData, string boundary) {
            System.IO.Stream stream=new ByteArrayStream(mimeMultipartData, 0);
            Mime.UnbufferedReader reader=new UnbufferedReader(stream);
            return GetParts(reader, boundary);
        }
        public static IEnumerable<MultipartPart> GetParts(Mime.UnbufferedReader streamReader, bool useOnlyASCII, Encoding customEncoding = null) {
            long startPosition = streamReader.BaseStream.Position;
            //find out the boundary and call the GetParts with boundary
            System.Collections.Specialized.NameValueCollection attributes;
            MultipartPart.ReadHeaderAttributes(streamReader.BaseStream, streamReader.BaseStream.Position, out attributes, useOnlyASCII, null);

            SharedUtils.Logger.Log("Extracted attributes at offset " + startPosition + " : " + String.Join(",", attributes.AllKeys), SharedUtils.Logger.EventLogEntryType.Information);
            if (attributes["charset"] != null) {
                try {
                    customEncoding = Encoding.GetEncoding(attributes["charset"]);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error getting encoding for charset \"" + attributes["charset"] + "\" in MIME part. " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                }
            }
            string boundary = attributes["boundary"];
            if (boundary != null) {
                streamReader.BaseStream.Position = startPosition;
                //int partsReturned = 0;
                foreach (MultipartPart part in GetParts(streamReader, boundary, useOnlyASCII, customEncoding)) {
                    SharedUtils.Logger.Log("MIME part extracted at offset " + startPosition + " with boundary \"" + boundary + "\"", SharedUtils.Logger.EventLogEntryType.Information);
                    yield return part;
                    //partsReturned++;
                }
                //if(partsReturned == 0)//return a single part
                //    yield return new MultipartPart(streamReader.BaseStream, streamReader.BaseStream.Position, (int)(streamReader.BaseStream.Length - streamReader.BaseStream.Position), customEncoding);
            }
            else {
                SharedUtils.Logger.Log("Extracting MIME part at offset " + streamReader.BaseStream.Position + " with no boundary", SharedUtils.Logger.EventLogEntryType.Information);
                //return a single part
                yield return new MultipartPart(streamReader.BaseStream, streamReader.BaseStream.Position, (int)(streamReader.BaseStream.Length - streamReader.BaseStream.Position), customEncoding, useOnlyASCII);
                //yield break;
            }

        }
        public static IEnumerable<MultipartPart> GetParts(Mime.UnbufferedReader streamReader, string boundary) {
            return GetParts(streamReader, boundary, Utils.SystemHelper.IsRunningOnMono());
        }
        public static IEnumerable<MultipartPart> GetParts(Mime.UnbufferedReader streamReader, string boundary, bool useOnlyASCII, Encoding customEncoding = null) {

            string interPartBoundary="--"+boundary;
            string finalBoundary="--"+boundary+"--";
            while(!streamReader.EndOfStream){
                long partStartPosition=streamReader.BaseStream.Position;
                int partLength=0;
                string line=streamReader.ReadLine(MultipartPart.MAX_LINE_LENGTH, customEncoding);
                if (line == null)
                    SharedUtils.Logger.Log("Null MIME Part line found at index " + partStartPosition, SharedUtils.Logger.EventLogEntryType.Information);
                else if (line.Length == 0)
                    SharedUtils.Logger.Log("Zero MIME Part line lenght found at index " + partStartPosition, SharedUtils.Logger.EventLogEntryType.Information);
                else if (line.Length == MultipartPart.MAX_LINE_LENGTH)
                    SharedUtils.Logger.Log("Max MIME Part line lenght found at index " + partStartPosition + ", data is probably truncated", SharedUtils.Logger.EventLogEntryType.Warning);

                while (line!=interPartBoundary && line!=finalBoundary){
                    partLength=(int)(streamReader.BaseStream.Position-2-partStartPosition);//-2 is in order to remove the CRLF at the end
                    line=streamReader.ReadLine(MultipartPart.MAX_LINE_LENGTH, customEncoding);
                    if (line == null)
                        SharedUtils.Logger.Log("Null MIME Part line found in " + partLength + " sized part", SharedUtils.Logger.EventLogEntryType.Information);
                    else if (line.Length == 0)
                        SharedUtils.Logger.Log("Zero MIME Part line lenght found in " + partLength + " sized part", SharedUtils.Logger.EventLogEntryType.Information);
                    else if (line.Length == MultipartPart.MAX_LINE_LENGTH)
                        SharedUtils.Logger.Log("Max MIME Part line lenght found in " + partLength + " sized part, data is probably truncated", SharedUtils.Logger.EventLogEntryType.Warning);


                    if (line==null) {
                        if (partLength > 0) {
                            byte[] partData = new byte[partLength];
                            streamReader.BaseStream.Position = partStartPosition;
                            streamReader.BaseStream.Read(partData, 0, partData.Length);
                            yield return new MultipartPart(partData, customEncoding, useOnlyASCII);
                        }
                        else
                            SharedUtils.Logger.Log("Empty MIME part at offset " + streamReader.BaseStream.Position + " with boundary \"" + boundary + "\"", SharedUtils.Logger.EventLogEntryType.Warning);
                        yield break;//end of stream
                        //break;
                    }
                }
                long nextPartStartPosition=streamReader.BaseStream.Position;

                if(partLength>0){
                    byte[] partData=new byte[partLength];
                    streamReader.BaseStream.Position=partStartPosition;
                    streamReader.BaseStream.Read(partData, 0, partData.Length);
                    MultipartPart part = new MultipartPart(partData, customEncoding, useOnlyASCII);

                    if(part.Attributes["Content-Type"]!=null && part.Attributes["Content-Type"].Contains("multipart") && part.Attributes["boundary"]!=null && part.Attributes["boundary"]!=boundary) {
                        foreach(MultipartPart internalPart in GetParts(part.Data, part.Attributes["boundary"]))
                            yield return internalPart;
                    }
                    else
                        yield return part;
                }
                
                streamReader.BaseStream.Position=nextPartStartPosition;
                if(line==finalBoundary)
                    break;
            }
        }
    }
}
