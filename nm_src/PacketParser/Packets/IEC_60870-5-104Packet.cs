using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Packets {

    /**
     * Many thanks to Aivar Liimets from Martem for the help with IEC-104!
     **/
    public class IEC_60870_5_104Packet : AbstractPacket, ISessionPacket {
        /**
         *        ^ START: 68H
         *      A | Length of the APDU (max. 253) Min 4??
         *   ^  P | Control field octet 1
         * A |  C | Control field octet 2
         * P |  I | Control field octet 3
         * D |    v Control field octet 4
         * U |    ^
         *   |    |
         *   |  ASDU (defined in 104 and 101 standards)
         *  ...  ...
         *   |    |
         *   v    v
         *   
         * 
         *  The ASDU typically look like this (IEC 101 7.1):
         *  
         *  1 2 3 4 5 6 7 8 
         * | Type ID       |  ^
         * |0| Nr. objects |  |
         * | Cause TX...   | DATA UNIT IDENTIFIER
         *   ...Cause TX   |  |  (optional Originator Address, often 0)
         * | ASDU Addr...     |
         *   ...ASDU Addr  |  v
         * | IOA ...          ^
         *   ...IOA...        |
         *   ...IOA        | INFORMATION OBJECT 1
         * | Value .....      |
         *   ...Value...   |  v
         *   
         *   
         * 
         * Cause TX is 2 bytes long per default (1 byte cause, and 1 byte Originator address).
         * Cause TX is defined in  60870-5-101 7.2.3
         * 
         * ASDU Address (aka Common Address of ASDU) is 2 bytes long per default and is
         * defined in Defined in 60870-5-101 7.2.4
         * "Octet 4 and optionally 5 of the DATA UNIT IDENTIFIER of the ASDU define the station address
         *  which is specified in the following. The length of the COMMON ADDRESS (one or two octets)
         *  is a parameter which is fixed per system."
         *  
         * IOA (INFORMATION OBJECT ADDRESS) is 3 bytes long per default and is Defined in 60870-5-101 7.2.5
         * "Octet 1, optionally 2 and optionally 3 of the INFORMATION OBJECT are defined in the following.
         *  The length of the INFORMATION OBJECT ADDRESS (one, two or three octets) is a parameter which
         *  is fixed per system."
         * 
         * 
         **/

        /**
         * CAUSE OF TRANSMISSION:= CP16{Cause,P/N,T,Originator Address (opt)}
         * Cause := UI6[1..6]<0..63>
         * <0> := not defined
         * <1..63> := number of cause
         * <1..47> := for standard definitions of this companion standard (compatible range) see Table 14
         * <48..63> := for special use (private range)
         * 
         * Cause := UI6[1..6]<0..63>
         * <0> := not used
         * <1> := periodic, cyclic per/cyc
         * <2> := background scan3 back
         * <3> := spontaneous spont
         * <4> := initialized init
         * <5> := request or requested req
         * <6> := activation act
         * <7> := activation confirmation actcon
         * <8> := deactivation deact
         * <9> := deactivation confirmation deactcon
         * <10> := activation termination actterm
         * <11> := return information caused by a remote command retrem
         * <12> := return information caused by a local command retloc
         * <13> := file transfer file
         * <14..19> := reserved for further compatible definitions
         * <20> := interrogated by station interrogation inrogen
         * <21> := interrogated by group 1 interrogation inro1
         * <22> := interrogated by group 2 interrogation inro2
         * <23> := interrogated by group 3 interrogation inro3
         * <24> := interrogated by group 4 interrogation inro4
         * <25> := interrogated by group 5 interrogation inro5
         * <26> := interrogated by group 6 interrogation inro6
         * <27> := interrogated by group 7 interrogation inro7
         * <28> := interrogated by group 8 interrogation inro8
         * <29> := interrogated by group 9 interrogation inro9
         * <30> := interrogated by group 10 interrogation inro10
         * <31> := interrogated by group 11 interrogation inro11
         * <32> := interrogated by group 12 interrogation inro12
         * <33> := interrogated by group 13 interrogation inro13
         * <34> := interrogated by group 14 interrogation inro14
         * <35> := interrogated by group 15 interrogation inro15
         * <36> := interrogated by group 16 interrogation inro16
         * <37> := requested by general counter request reqcogen
         * <38> := requested by group 1 counter request reqco1
         * <39> := requested by group 2 counter request reqco2
         * <40> := requested by group 3 counter request reqco3
         * <41> := requested by group 4 counter request reqco4
         * <42..43> := reserved for further compatible definitions
         * <44> := unknown type identification
         * <45> := unknown cause of transmission
         * <46> := unknown common address of ASDU
         * <47> := unknown information object address
         * <48..63> := for special use (private range)
         * 
         * */

        internal class SystemSettings {
            internal readonly bool causeOfTransmissionHasOriginatorAddress;//default = true
            internal readonly int asduAddressLength;//The default length of ASDU address is 2 octets
            internal readonly int ioaLength;//default = 3

            internal SystemSettings(bool causeOfTransmissionHasOriginatorAddress, int asduAddressLength, int ioaLenght) {
                this.causeOfTransmissionHasOriginatorAddress = causeOfTransmissionHasOriginatorAddress;
                this.asduAddressLength = asduAddressLength;
                this.ioaLength = ioaLenght;
            }
        }

        internal enum CauseOfTransmissionEnum : byte {
            not_used = 0,
            per_cyc = 1,
            back = 2,
            spont = 3,
            init = 4,
            req = 5,
            act = 6,
            actcon = 7,
            deact = 8,
            deactcon = 9,
            actterm = 10,
            retrem = 11,
            retloc = 12,
            file = 13,

            inrogen = 20,
            inro1 = 21,
            inro2 = 22,
            inro3 = 23,
            inro4 = 24,
            inro5 = 25,
            inro6 = 26,
            inro7 = 27,
            inro8 = 28,
            inro9 = 29,
            inro10 = 30,
            inro11 = 31,
            inro12 = 32,
            inro13 = 33,
            inro14 = 34,
            inro15 = 35,
            inro16 = 36,
            reqcogen = 37,
            reqco1 = 38,
            reqco2 = 39,
            reqco3 = 40,
            reqco4 = 41,

            unknown_type_identification = 44,
            unknown_cause_of_transmission = 45,
            unknown_common_address_of_ASDU = 46,
            unknown_information_object_address = 47
        }

        private static readonly SystemSettings defaultSystemSettings = new SystemSettings(true, 2, 3);
        //private static readonly SystemSettings defaultSystemSettings = new SystemSettings(true, 1, 2);

        private const int minApduLenght = 4;
        private const int maxApduLength = 253;
        private const byte APDU_START_MAGIC_VALUE = 0x68;
        private byte causeOfTransmission = 0; //IEC-101 7.2.3 Cause of transmission
        internal int AsduAddress { get; } = 0;//IEC-101 7.2.4 COMMON ADDRESS OF ASDUs

        internal byte ApduLength { get; } = 0;
        internal byte? AsduTypeID { get; }
        internal byte AsduInformationObjectCount { get; } = 0;
        internal bool AsduInformationObjectCountIsElementCount { get; } = false;
        internal CauseOfTransmissionEnum CauseOfTransmission { get { return (CauseOfTransmissionEnum)this.causeOfTransmission; } }
        internal bool CauseOfTransmissionNegativeConfirm { get; }
        internal bool CauseOfTransmissionTest { get; }
        internal byte[] AsduData { get; } = null;
        internal SystemSettings Settings { get; } = defaultSystemSettings;


        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            try {
                if (parentFrame.Data[packetStartIndex] != APDU_START_MAGIC_VALUE)
                    return false;
                else {
                    result = new IEC_60870_5_104Packet(parentFrame, packetStartIndex, packetEndIndex);
                    return true;
                }


            }
            catch (Exception e) {
                SharedUtils.Logger.Log("Exception when parsing frame " + parentFrame.FrameNumber + " as IEC-104 packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                return false;
            }
        }

        internal IEC_60870_5_104Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IEC 60870-5-104") {
            if (packetEndIndex - packetStartIndex > minApduLenght) {
                if (parentFrame.Data[packetStartIndex] != APDU_START_MAGIC_VALUE)
                    throw new Exception("APCI must start with 0x68 (104)");
                this.ApduLength = parentFrame.Data[packetStartIndex + 1];
                if (this.ApduLength >= minApduLenght && this.ApduLength <= maxApduLength) {
                    //TODO läs ut datat här!
                    int asduLength = this.ApduLength - 4;


                    if (asduLength > 0) {
                        int asduOffset = packetStartIndex + 6;
                        this.AsduTypeID = parentFrame.Data[asduOffset];
                        //this.Attributes.Add("ASDU ID", this.asduTypeID.ToString());
                        this.AsduInformationObjectCount = (byte)(parentFrame.Data[asduOffset + 1] & 0x7f);//7 bits
                        this.AsduInformationObjectCountIsElementCount = (parentFrame.Data[asduOffset + 1] & 0x80) == 0x80;//1 bit
                        this.causeOfTransmission = (byte)(parentFrame.Data[asduOffset + 2] & 0x3f);//6 bits
                        this.CauseOfTransmissionNegativeConfirm = (parentFrame.Data[asduOffset + 2] & 0x40) == 0x40;//1 bit
                        this.CauseOfTransmissionTest = (parentFrame.Data[asduOffset + 2] & 0x80) == 0x80;//1 bit
                        int asduAddressIndex = asduOffset + 3;
                        if (this.Settings.causeOfTransmissionHasOriginatorAddress)
                            asduAddressIndex++;
                        this.AsduAddress = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, asduAddressIndex, Settings.asduAddressLength, true);
                        this.AsduData = new byte[asduLength];
                        Array.Copy(parentFrame.Data, asduOffset, AsduData, 0, asduLength);
                    }
                }

            }
        }




        public bool PacketHeaderIsComplete {
            get { throw new NotImplementedException(); }
        }

        public int ParsedBytesCount {
            get { throw new NotImplementedException(); }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else
                yield break;
        }

        #region InformationElements
        //IEC-101 7.2.6 Information elements

        interface IInformationElement {
            string ShortName { get; }

            /// <summary>
            /// Length in bytes of the IE
            /// </summary>
            int Length { get; }

            string ToString();
        }

        internal class SIQ : IInformationElement {
            //IEC-101 7.2.6.1 Single-point information (IEV 371-02-07) with quality descriptor

            private bool spi;//0=off, 1=on
            private QualityDescriptorNibble qd;



            public string ShortName {
                get { return "SIQ"; }
            }

            public int Length {
                get { return 1; }
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                //sb.Append("Value: ");
                if (this.spi)
                    sb.Append("ON");
                else
                    sb.Append("OFF");
                sb.Append(" (" + this.qd.ToString() + ")");
                return sb.ToString();

            }

            public SIQ(byte[] asduBytes, int offset) {
                byte b = asduBytes[offset];
                this.spi = (b & 0x01) == 0x01;
                this.qd = new QualityDescriptorNibble(asduBytes, offset);
            }
        }

        internal class DIQ : IInformationElement {
            //IEC-101 7.2.6.2 Double-point information (IEV 371-02-08) with quality descriptor

            internal enum DpiState { INTERMEDIATE = 0, OFF = 1, ON = 2, INDETERMINATE = 3 }

            private DpiState dpi;//2 bytes

            private QualityDescriptorNibble qd;


            public string ShortName {
                get { return "DIQ"; }
            }

            public int Length {
                get { return 1; }
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                //sb.Append("Value: ");
                sb.Append(dpi.ToString());
                sb.Append(" (" + this.qd.ToString() + ")");
                return sb.ToString();

            }

            public DIQ(byte[] asduBytes, int offset) {
                byte b = asduBytes[offset];
                this.dpi = (DpiState)(b & 0x03);//2 bits
                //skip 2 bits
                this.qd = new QualityDescriptorNibble(asduBytes, offset);
            }
        }

        internal class BSI : IInformationElement {
            //7.2.6.13 Binary state information (IEV 371-02-03) 32 bit
            //readonly System.Collections.BitArray bsi;
            readonly bool[] bsi;
            readonly uint bsiUint;

            public string ShortName { get; } = "BSI";

            public int Length { get; } = 4;

            public BSI(byte[] asduBytes, int offset) {
                //this.bsi = new System.Collections.BitArray(asduBytes.Skip(offset).Take(4).ToArray());
                this.bsi = Utils.ByteConverter.ToBoolArray(asduBytes.Skip(offset).Take(this.Length).ToArray());
                this.bsiUint = Utils.ByteConverter.ToUInt32(asduBytes, offset, 4, true);
            }

            public override string ToString() {
                /*
                string[] bsiValues = new string[bsi.Length];
                for (int i = 0; i < bsi.Length; i++) {
                    if (bsi[i])
                        bsiValues[i] = "1";
                    else
                        bsiValues[i] = "0";
                }
                return string.Join(" ", bsiValues);
                */
                return "0x" + this.bsiUint.ToString("x8");
            }
        }
        internal class CP56Time2a : IInformationElement {
            //7.2.6.18
            //Seven octet binary time

            /**
             * CP56Time2a := CP56{
             *  milliseconds, 16 bit
             *  +=2
             *  minutes, 6 bit
             *  RES1, 1 bit?
             *  invalid, 1 bit
             *  ++
             *  hours, 5 bit
             *  RES2,
             *  summer time,
             *  ++
             *  day of month, 5 bit
             *  day of week, 3 bit
             *  ++
             *  months, 4 bit
             *  RES3,
             *  ++
             *  years, 7 bit
             *  RES4
             * }
             **/

            private DateTime timestamp;

            public string ShortName {
                get { return "CP56Time2a"; }
            }

            public int Length {
                get { return 7; }
            }

            public CP56Time2a(byte[] asduBytes, int offset) {
                int milliseconds = Utils.ByteConverter.ToUInt16(asduBytes, offset, true);
                int seconds = milliseconds / 1000;
                milliseconds = milliseconds % 1000;
                offset += 2;
                int minutes = asduBytes[offset] & 0x3f;
                offset++;
                int hours = asduBytes[offset] & 0x1f;
                offset++;
                int day = asduBytes[offset] & 0x1f;
                offset++;
                int month = asduBytes[offset] & 0x0f;
                offset++;
                int year = 2000 + (asduBytes[offset] & 0x7f) % 100;
                offset++;
                this.timestamp = new DateTime(year, month, day, hours, minutes, seconds, milliseconds);
            }

            public override string ToString() {
                //return this.timestamp.ToUniversalTime().ToString("yyyy'-'MM'-'dd' 'HH':'mm':'ss'.'fff UTC");
                return this.timestamp.ToUniversalTime().ToString("o");
            }

        }

        internal class SCO : IInformationElement {
            //7.2.6.15 Single command (IEV 371-03-02)

            private bool scs;//0 = OFF, 1=ON
            //1 reserved bit
            private QOC qoc;//6bits - see 7.2.6.26 QOC

            public string ShortName {
                get { return "SCO"; }
            }

            public int Length {
                get { return 1; }
            }

            public SCO(byte[] asduBytes, int offset) {
                this.scs = (asduBytes[offset] & 0x01) == 0x01;
                this.qoc = new QOC(asduBytes, offset);
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                if (this.scs)
                    sb.Append("ON ");
                else
                    sb.Append("OFF ");
                sb.Append("(" + qoc.ToString() + ")");
                return sb.ToString();
            }
        }

        internal class DCO : IInformationElement {
            //7.2.6.16 Double command (IEV 371-03-03)

            private int dcs;//2 bits
            /**
             * DCS=Double command state := UI2[1..2]<0..3> (Type 1.1)
             * <0> := not permitted
             * <1> := OFF
             * <2> := ON
             * <3> := not permitted
             * */
            private QOC qoc;//6bits - see 7.2.6.26 QOC

            public string ShortName {
                get { return "DCO"; }
            }

            public int Length {
                get { return 1; }
            }

            public DCO(byte[] asduBytes, int offset) {
                this.dcs = (asduBytes[offset] & 0x03);
                this.qoc = new QOC(asduBytes, offset);
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                if (dcs == 1)
                    sb.Append("OFF");
                else if (dcs == 2)
                    sb.Append("ON");
                else
                    sb.Append(dcs.ToString());
                sb.Append(" (" + qoc.ToString() + ")");
                return sb.ToString();
            }
        }

        internal class RCO : IInformationElement {

            private byte rcs;
            private QOC qoc;
            public string ShortName { get; } = "RCO";

            public int Length { get; } = 1;

            public RCO(byte[] asduBytes, int offset) {
                this.rcs = (byte)(asduBytes[offset] & 0x03);
                this.qoc = new QOC(asduBytes, offset);
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                if (this.rcs == 0x01)
                    sb.Append("DOWN");
                else if (this.rcs == 0x02)
                    sb.Append("UP");
                else
                    sb.Append("?");
                sb.Append(" (" + qoc.ToString() + ")");
                return sb.ToString();
            }
        }

        internal class SOF : IInformationElement {
            private byte sofValue;

            //7.2.6.38 Status of file

            public byte Status {
                get {
                    return (byte)(this.sofValue & 0x1f);//5 bits
                }
            }
            public bool LastFileOrDirectory { get; }
            public bool IsDirectory { get; }
            public bool ActiveTransfer { get; }

            public string ShortName { get; } = "SOF";

            public int Length { get; } = 1;

            public SOF(byte[] asduBytes, int offset) {
                this.sofValue = asduBytes[offset];
                //5 least significant bits is status
                this.LastFileOrDirectory = (this.sofValue & 0x20) == 0x20;
                this.IsDirectory = (this.sofValue & 0x40) == 0x40;
                this.ActiveTransfer = (this.sofValue & 0x80) == 0x80;
            }

            public override string ToString() {
                List<string> sofStrings = new List<string> {
                    this.Status.ToString(),
                };
                if (this.LastFileOrDirectory)
                    sofStrings.Add("last");
                else
                    sofStrings.Add("not last");
                if (this.IsDirectory)
                    sofStrings.Add("dir");
                else
                    sofStrings.Add("file");
                if (this.ActiveTransfer)
                    sofStrings.Add("transfer active");
                else
                    sofStrings.Add("awaits transfer");
                return String.Join(", ", sofStrings);
            }
        }

        internal class QOS : IInformationElement {
            //7.2.6.39 Qualifier of set-point command

            private int ql;//7 bits
            /**
             * <0> := default
             * <1..63> := reserved for standard definitions of this companion standard (compatible range)
             * <64..127> := reserved for special use (private range)
             **/
            private bool select;
            /*
             * <0> := execute
             * <1> := select
             * */

            public QOS(byte[] asduBytes, int offset) {
                //skip 2 least significant bits

                //7 bits QL
                this.ql = (asduBytes[offset] & 0x7f);
                this.select = (asduBytes[offset] & 0x80) == 0x80;//most significant bit is SELECT
            }

            public string ShortName {
                get { return "QOS"; }
            }

            public int Length {
                get { return 1; }
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                if (ql > 0) {
                    sb.Append(ql.ToString());
                    sb.Append(", ");
                }
                if (this.select)
                    sb.Append("Select");
                else
                    sb.Append("Execute");
                return sb.ToString();
            }
        }

        internal class QOC : IInformationElement {
            //7.2.6.26 Qualifier of command

            private int qu;//5 bits
            /**
             * <0> := no additional definition
             * <1> := short pulse duration (circuit-breaker), duration determined by a system parameter in the outstation
             * <2> := long pulse duration, duration determined by a system parameter in the outstation
             * <3> := persistent output
             * <4..8> := reserved for standard definitions of this companion standard (compatible range)
             * <9..15> := reserved for the selection of other predefined functions 6
             * <16..31> := reserved for special use (private range)
             * */

            private bool select;//0 = execute, 1 = select

            public string ShortName {
                get { return "QOC"; }
            }

            public int Length {
                get { return 1; }
            }

            public QOC(byte[] asduBytes, int offset) {
                //skip 2 least significant bits

                //5 bits QU
                this.qu = (asduBytes[offset] & 0x7c) >> 2;
                this.select = (asduBytes[offset] & 0x80) == 0x80;//most significant bit is SELECT
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                //sb.Append("Qualifier: ");
                //sb.Append(qu.ToString());
                
                if (this.qu == 1)
                    sb.Append("Short Pulse");
                else if (this.qu == 2)
                    sb.Append("Long Pulse");
                else if (this.qu == 3)
                    sb.Append("Persistent Output");
                else if(this.qu > 3)
                    sb.Append(qu.ToString());
                if(sb.Length > 0)
                    sb.Append(", ");
                if (this.select)
                    sb.Append("Select");
                else
                    sb.Append("Execute");
                return sb.ToString();
            }
        }

        internal class QOI : IInformationElement {
            //7.2.6.22 Qualifier of interrogation
            private byte qoi;
            /**
             * QOI := UI8[1..8]<0..255> (Type 1.1)
             * <0> := not used
             * <1..19> := reserved for standard definitions of this companion standard (compatible range)
             * <20> := Station interrogation (global)
             * <21> := Interrogation of group 1
             * <22> := Interrogation of group 2
             * <23> := Interrogation of group 3
             * etc....
             * <36> := Interrogation of group 16
             * <37..63> := reserved for standard definitions of this companion standard (compatible range)
             * <64..255> := reserved for special use (private range)
             * */
            public string ShortName {
                get { return "QOI"; }
            }

            public int Length {
                get { return 1; }
            }

            public QOI(byte[] asduBytes, int offset) {
                this.qoi = asduBytes[offset];
            }

            public override string ToString() {
                if (this.qoi == 20)
                    return "Station Interrogation (global)";
                else if (this.qoi > 20 && this.qoi < 37) {
                    int group = this.qoi - 20;
                    return "Interrogation of Group " + group.ToString();
                }
                else
                    return "QOI " + qoi.ToString();
            }
        }

        internal class QCC : IInformationElement {
            //7.2.6.23 Qualifier of counter interrogation command

            private byte rqt, frz;

            public string ShortName { get; } = "QCC";
            public int Length { get; } = 1;
            public QCC(byte[] asduBytes, int offset) {
                this.rqt = (byte)(asduBytes[offset] & 0x3f);//6 bits
                this.frz = (byte)(asduBytes[offset] >> 6);//2 bits
             }
            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                if (this.rqt == 0)
                    sb.Append("No Counter Group");
                else if (this.rqt < 5)
                    sb.Append("Counter Group " + this.rqt);
                else if (this.rqt == 5)
                    sb.Append("General Counter");
                else
                    sb.Append("RQT " + this.rqt);
                sb.Append(", ");
                if (this.frz == 0)
                    sb.Append("Read");
                else if (this.frz == 1)
                    sb.Append("Freeze without Reset ");
                else if (this.frz == 2)
                    sb.Append("Freeze with Reset ");
                else if (this.frz == 3)
                    sb.Append("Reset ");
                return sb.ToString();
            }
        }

        internal class SVA : IInformationElement {
            /**
             * IEC 101
             * 7.2.6.7 Scaled value
             * SVA := I16[1..16]<–2^15..+2^15–1>
             * */
            private short value;

            public SVA(byte[] asduBytes, int offset) {
                this.value = (short)(asduBytes[offset] + (asduBytes[offset + 1] << 8));
            }

            public virtual string ShortName {
                get { return "SVA"; }
            }

            public int Length {
                get { return 2; }
            }

            internal short Value {
                get { return this.value; }
            }

            public override string ToString() {
                return this.value.ToString();
            }
        }

        internal class NVA : SVA {
            private const double NORMALIZATION_FACTOR = -1.0 / Int16.MinValue;
            private static System.Globalization.NumberFormatInfo nfiSingleton = null;

            //private short value;//not normalized

            internal System.Globalization.NumberFormatInfo PercentFormat {
                get {
                    if (nfiSingleton == null) {
                        nfiSingleton = new System.Globalization.CultureInfo("en-US", false).NumberFormat;
                        nfiSingleton.PercentDecimalDigits = 3;
                    }
                    return nfiSingleton;
                }
            }

            //7.2.6.6 Normalized value (fixed point)
            //NVA := F16[1..16]<–1..+1 –2–15> (Type 4.1)
            //short / 32768
            public override string ShortName {
                get { return "NVA"; }
            }


            /*
            public override int Length {
                get { return 2; }
            }*/

            public NVA(byte[] asduBytes, int offset) : base(asduBytes, offset) {
                //nothing more needed here
            }

            public override string ToString() {
                //return (this.value * NORMALIZATION_FACTOR).ToString("F5");
                return (base.Value * NORMALIZATION_FACTOR).ToString("P", this.PercentFormat);
            }
        }

        internal class R32_IEEE_STD_754 : IInformationElement {
            //IEEE_754_Binary32Float 
            //Short floating point number
            //R32-IEEE STD 754 := R32.23{Fraction,Exponent,Sign}

            //private int value;
            //private System.Collections.BitArray bits;
            private float floatValue;

            public R32_IEEE_STD_754(byte[] asduBytes, int offset) {
                //this.value = (int)Utils.ByteConverter.ToUInt32(asduBytes, offset, 4, true);
                //this.bits = new System.Collections.BitArray(new int[] { value });
                this.floatValue = BitConverter.ToSingle(asduBytes, offset);
            }

            public string ShortName {
                get { return "R32-IEEE STD 754"; }
            }

            public int Length {
                get { return 4; }
            }

            public override string ToString() {
                return this.floatValue.ToString();
            }
        }

        internal class QPM : IInformationElement {
            //QPM = Qualifier of parameter of measured values, defined in 7.2.6.24
            private byte kpa;
            public string ShortName {
                get { return "QPM"; }
            }

            public int Length {
                get { return 1; }
            }

            public QPM(byte[] asduBytes, int offset) {
                this.kpa = (byte)(asduBytes[offset] & 0x3f);
            }
            public override string ToString() {
                if (this.kpa == 0)
                    return "Not Used";
                else if (this.kpa == 1)
                    return "Threshold";
                else if (this.kpa == 2)
                    return "Smoothing";
                else if (this.kpa == 3)
                    return "Low Limit";
                else if (this.kpa == 4)
                    return "High Limit";
                else
                    return "KPA " + this.kpa;
            }
        }

        internal class QDS : IInformationElement {
            //7.2.6.3 Quality descriptor (separate octet)
            private bool ov;//overflow
            private QualityDescriptorNibble qd;

            public string ShortName {
                get { return "QDS"; }
            }

            public int Length {
                get { return 1; }
            }

            public QDS(byte[] asduBytes, int offset) {
                this.ov = (asduBytes[offset] & 0x01) == 0x01;
                this.qd = new QualityDescriptorNibble(asduBytes, offset);
            }
            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                if (this.ov)
                    sb.Append("Overflow, ");
                else
                    sb.Append("No Overflow, ");
                sb.Append(qd.ToString());
                return sb.ToString();
            }
        }

        public class VTI : IInformationElement {
            //7.2.6.5 Value with transient state indication
            private sbyte vtiValue;//7 bit signed integer
            public string ShortName { get; } = "VTI";

            public int Length { get; } = 1;

            public VTI(byte[] asduBytes, int offset) {
                this.vtiValue = (sbyte)(asduBytes[offset] << 1);
                //this.vtiValue >>= 1;//or divide by 2
                this.vtiValue /= 2;
            }

            public override string ToString() {
                return vtiValue.ToString();
            }
        }

        /// <summary>
        /// Internal class to be used within other IInformationElements.
        /// Parses the 4 most significant bits.
        /// Contains BL SB NT IV
        /// </summary>
        internal class QualityDescriptorNibble : IInformationElement {
            private bool bl;//0=not blocked, 1=blocked
            private bool sb;//0=not substituted, 1=substituted
            private bool nt;//0=topical, 1=not topical
            private bool iv;//0=valid, 1=invalid

            public string ShortName {
                get { return null; }
            }

            public int Length {
                get { return 1; }
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                if (this.bl)
                    sb.Append("Blocked");
                else
                    sb.Append("Not Blocked");
                sb.Append(", ");
                if (this.sb)
                    sb.Append("Substituted");
                else
                    sb.Append("Not Substituted");
                sb.Append(", ");
                if (this.nt)
                    sb.Append("Not Topical");
                else
                    sb.Append("Topical");
                sb.Append(", ");
                if (this.iv)
                    sb.Append("Invalid");
                else
                    sb.Append("Valid");
                return sb.ToString();
            }

            public QualityDescriptorNibble(byte[] asduBytes, int offset) {
                byte b = asduBytes[offset];

                this.bl = (b & 0x10) == 0x10;//BS1[5]<0..1>
                this.sb = (b & 0x20) == 0x20;
                this.nt = (b & 0x40) == 0x40;
                this.iv = (b & 0x80) == 0x80;
            }
        }

        internal class SCQ : IInformationElement {
            //7.2.6.30 Select and call qualifier

            enum Command : byte {
                select_file = 1,
                request_file = 2,
                deactivate_file = 3,
                delete_file = 4,
                select_section = 5,
                request_section = 6,
                deactivate_section = 7
            }

            enum Error : byte {
                requested_memory_space_not_available = 1,
                checksum_failed = 2,
                unexpected_communication_service = 3,
                unexpected_name_of_file = 4,
                unexpected_name_of_section = 5
            }

            private readonly byte command;
            private readonly byte error;

            public string ShortName { get; } = "SCQ";

            public int Length { get; } = 1;

            public SCQ(byte[] asduBytes, int offset) {
                this.command = (byte)(asduBytes[offset] & 0x0f);
                this.error = (byte)(asduBytes[offset] >> 4);
            }

            public override string ToString() {
                List<string> returnStrings = new List<string>();
                if (Enum.IsDefined(typeof(Command), this.command))
                    returnStrings.Add(((Command)this.command).ToString());
                if (Enum.IsDefined(typeof(Error), this.error))
                    returnStrings.Add(((Error)this.error).ToString());
                return string.Join(", ", returnStrings);
            }

        }

        internal class NOF : IInformationElement {
            //7.2.6.33 Name of file
            public string ShortName { get; } = "NOF";
            public int Length { get; } = 2;

            public ushort FileID { get; private set; }

            public NOF(byte[] asduBytes, int offset) {
                this.FileID = Utils.ByteConverter.ToUInt16(asduBytes, offset, true);
            }

            public override string ToString() {
                return this.FileID.ToString();
            }
        }

        internal class LOF : IInformationElement {
            //7.2.6.35 Length of file or section

            public uint FileOrSectionLength { get; private set; }

            public string ShortName { get; } = "LOF";
            public int Length { get; } = 3;

            public LOF(byte[] asduBytes, int offset) {
                this.FileOrSectionLength = Utils.ByteConverter.ToUInt32(asduBytes, offset, 3, true);
            }
        }

        internal class FRQ : IInformationElement {
            //7.2.6.28 File ready qualifier

            private bool positiveConfirm;

            /**
             * UI7[1..7]<0..127> (Type 1.1)
<0> := default
<1..63> := reserved for standard definitions of this companion standard
(compatible range)
<64..127> := reserved for special use (private range)
BS1[8]<0..1> (Type 6)
<0> := positive confirm of select, request, deactivate or delete
<1> := negative confirm of select, request, deactivate or delete
            */
            public string ShortName { get; } = "FRQ";
            public int Length { get; } = 1;

            public FRQ(byte[] asduBytes, int offset) {
                byte unknown = (byte)(asduBytes[offset] & 0x7f);
                this.positiveConfirm = (asduBytes[offset] & 0x80) == 0;
            }

            public override string ToString() {
                if (this.positiveConfirm)
                    return "Ready";
                else
                    return "Not Ready";
            }

            #endregion
        }
    }
}
