using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace PacketParser.Mime {
    class MultipartPart {
        private System.Collections.Specialized.NameValueCollection attributes;
        //private System.Collections.Generic.List<byte> data;
        private byte[] data;

        public System.Collections.Specialized.NameValueCollection Attributes { get { return this.attributes; } }
        public byte[] Data { get { return data; } }

        internal static void ReadHeaderAttributes(System.IO.Stream stream, long partStartIndex, out System.Collections.Specialized.NameValueCollection attributes, bool useOnlyASCII, Encoding customEncoding = null) {
            stream.Position=partStartIndex;
            UnbufferedReader streamReader=new UnbufferedReader(stream);
            attributes=new System.Collections.Specialized.NameValueCollection();

            string line=streamReader.ReadLine(200, customEncoding);
            char[] headerParameterSeparators={ ';' };
            //TODO: parse attribute headers properly, i.e. the stuff BEFORE ";"
            while(line!=null && line.Length>0 && stream.Position < stream.Length) {//read the part headers
                string[] headerDataCollection=line.Split(headerParameterSeparators);
                bool skipNextLine = false;

                /**
                 * ==HEADER EXAMPLE 1 (SMTP)==
                 * Content-Type: application/octet-stream;
                 * .name="secretrendezvous.docx"
                 * Content-Transfer-Encoding: base64
                 * Content-Disposition: attachment;
                 * .filename="secretrendezvous.docx"
                 *
                 * ==HEADER EXAMPLE 2 (SMTP, part inside multipart/mixed) - notice the missing quotation marks around the filename
                 * Content-Type: application/zip
                 * Content-Disposition: attachment; filename=00000459735.zip
                 * Content-Transfer-Encoding: base64
                 * 
                 * ==HEADER EXAMPLE 3 (SMTP)==
                 * Content-Type: text/plain;
                 * .charset="iso-8859-1"
                 * Content-Transfer-Encoding: quoted-printable
                 * 
                 * ==HEADER EXAMPLE 4 (HTTP POST)==
                 * Content-Disposition: form-data; name="check_type_diff"
                 * 
                 * ==HEADER EXAMPLE 5 (HTTP POST)==
                 * Content-Disposition: form-data; name="image"; filename="C:\jx-3p.txt"
                 * Content-Type: text/plain
                 * 
                 * ==Another tricky RFC 2047 example==
                 * Subject: =?UTF-8?Q?[Bokserkomania]_V=C3=A4nligen_moderera:_"Slipy_w_ksi=C4=99?=  =?UTF-8?Q?=C5=BCyce"?=
                 * 
                 * ==UTF8 encoded filename in HTTP POST, RFC 5987==
                 * Content-Disposition: form-data; name="Filedata"; filename="测试文档-Document for test.docx"
                 * ^^--where filename is UTF8 encoded
                 *
                 * ==SMTP email with Simplified Chinese in attribute values== prior to this we've seen: charset="gb2312"
                 * Content-Type: application/octet-stream;
                 *         name="ºÎÀ½£­¸ß¼¶ÃØÊé¡¢ÖúÀíºÍÐÐÕþ¹ÜÀíÕß¹¤×÷Ð§ÂÊÌáÉýÑµÁ·Óª.zip"
                 * Content-Transfer-Encoding: base64
                 * Content-Disposition: attachment;
                 *         filename="ºÎÀ½£­¸ß¼¶ÃØÊé¡¢ÖúÀíºÍÐÐÕþ¹ÜÀíÕß¹¤×÷Ð§ÂÊÌáÉýÑµÁ·Óª.zip"
                 * 
                 * ==POP3 example with multi-line boundary in Content-Type==
                 * Content-Type: multipart/related; boundary="----MIME delimiter for [0x0d 0x0a]
                 *  sendEmail-118138.401377113"
                 *  
                 * ==SMTP example==
                 * Content-Type: text/plain; charset=utf-8; format=flowed
                 * content-transfer-encoding: quoted-printable
                 *  
                 *  ==SMTP example==
                 *  Content-Type: application/octet-stream; name="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                 *  Content-Transfer-Encoding: base64
                 * 
                 */

                for (int i=0; i<headerDataCollection.Length; i++) {
                    try {

                        if (headerDataCollection[i].Contains("=\"") && headerDataCollection[i].Length > headerDataCollection[i].IndexOf('\"') + 1) {
                            string parameterName = headerDataCollection[i].Substring(0, headerDataCollection[i].IndexOf('=')).Trim();
                            int length = headerDataCollection[i].LastIndexOf('\"') - headerDataCollection[i].IndexOf('\"') - 1;
                            while(length < 0 && line != null && line.Length > 0 && stream.Position < stream.Length) {
                                if (i == headerDataCollection.Length - 1) {
                                    //try reading the next line.
                                    line = streamReader.ReadLine(200, customEncoding);
                                    char quote = '\"';
                                    if (line.Contains("" + quote) && line.IndexOf(quote) == line.LastIndexOf(quote) && line.EndsWith("" + quote)) {
                                        headerDataCollection[i] += line;//append next line to value
                                        length = headerDataCollection[i].LastIndexOf('\"') - headerDataCollection[i].IndexOf('\"') - 1;
                                    }
                                    else {
                                        skipNextLine = true;
                                        break;
                                    }
                                }
                                else
                                    continue;//go to next parameter
                            }
                            string parameterValue = headerDataCollection[i].Substring(headerDataCollection[i].IndexOf('\"') + 1, length).Trim();
                            parameterValue = Rfc2047Parser.DecodeRfc2047Parts(parameterValue);
                            if (useOnlyASCII)
                                attributes.Add(Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterName), Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterValue));
                            else
                                attributes.Add(parameterName, parameterValue);
                        }
                        else if (headerDataCollection[i].Contains("name=") || headerDataCollection[i].Contains("charset=") || headerDataCollection[i].Contains("format=")) {
                            string parameterName = headerDataCollection[i].Substring(0, headerDataCollection[i].IndexOf('=')).Trim();
                            string parameterValue = headerDataCollection[i].Substring(headerDataCollection[i].IndexOf('=') + 1).Trim();
                            parameterValue = Rfc2047Parser.DecodeRfc2047Parts(parameterValue);
                            if (useOnlyASCII)
                                attributes.Add(Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterName), Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterValue));
                            else
                                attributes.Add(parameterName, parameterValue);
                        }
                        else if (headerDataCollection[i].Contains(": ")) {
                            string parameterName = headerDataCollection[i].Substring(0, headerDataCollection[i].IndexOf(':')).Trim();
                            string parameterValue = headerDataCollection[i].Substring(headerDataCollection[i].IndexOf(':') + 1).Trim();
                            parameterValue = Rfc2047Parser.DecodeRfc2047Parts(parameterValue);
                            if (useOnlyASCII)
                                attributes.Add(Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterName), Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterValue));
                            else
                                attributes.Add(parameterName, parameterValue);
                        }
                    }
                    catch (Exception e) {
                        SharedUtils.Logger.Log("Exception when parsing MIME data: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    }
                }
                if (skipNextLine)
                    skipNextLine = false;
                else
                    line = streamReader.ReadLine(200, customEncoding);
            }
      
        }

        internal MultipartPart(System.Collections.Specialized.NameValueCollection attributes) : this(attributes, new byte[0]) {
        }
        internal MultipartPart(System.Collections.Specialized.NameValueCollection attributes, byte[] data) {
            this.attributes=attributes;
            this.data=data;
        }
        internal MultipartPart(byte[] partData, Encoding customEncoding, bool useOnlyASCII) : this(new ByteArrayStream(partData, 0),0, partData.Length, customEncoding, useOnlyASCII){
            //nothing more...
        }

        internal MultipartPart(System.IO.Stream stream, long partStartIndex, int partLength, Encoding customEncoding, bool useOnlyASCII) {
            ReadHeaderAttributes(stream, partStartIndex, out this.attributes, useOnlyASCII, customEncoding);
            //read the part data
           this.data=new byte[partLength+partStartIndex-stream.Position];
           stream.Read(data, 0, data.Length);
        }

    }
}
