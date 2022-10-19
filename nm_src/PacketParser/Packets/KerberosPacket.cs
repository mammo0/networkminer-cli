using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Packets {
    public class KerberosPacket : AbstractPacket {



        //http://web.mit.edu/freebsd/head/crypto/heimdal/lib/asn1/krb5.asn1
        public enum MessageType : byte {
            krb_null = 0,//unknown
            krb_as_req = 10,//Request for initial authentication
            krb_as_rep = 11,// -- Response to KRB_AS_REQ request
            krb_tgs_req = 12,// -- Request for authentication based on TGT
            krb_tgs_rep = 13,// -- Response to KRB_TGS_REQ request
            krb_ap_req = 14,// -- application request to server
            krb_ap_rep = 15,// -- Response to KRB_AP_REQ_MUTUAL
            krb_safe = 20,// _- Safe(checksummed) application message
            krb_priv = 21,// -- Private(encrypted) application message
            krb_cred = 22,// -- Private(encrypted) message to forward credentials
            krb_error = 30// -- Error response
        }

        //http://web.mit.edu/freebsd/head/crypto/heimdal/lib/asn1/krb5.asn1
        public enum NameType : int {
            KRB5_NT_UNKNOWN = 0,//	-- Name type not known
            KRB5_NT_PRINCIPAL = 1,//	-- Just the name of the principal as in
            KRB5_NT_SRV_INST = 2,//	-- Service and other unique instance(krbtgt)
            KRB5_NT_SRV_HST = 3,//	-- Service with host name as instance
            KRB5_NT_SRV_XHST = 4,//	-- Service with host as remaining components
            KRB5_NT_UID = 5,//		-- Unique ID
            KRB5_NT_X500_PRINCIPAL = 6,// -- PKINIT
            KRB5_NT_SMTP_NAME = 7,//	-- Name in form of SMTP email name
            KRB5_NT_ENTERPRISE_PRINCIPAL = 10,// -- Windows 2000 UPN
            KRB5_NT_WELLKNOWN = 11,//	-- Wellknown
            KRB5_NT_ENT_PRINCIPAL_AND_ID = -130,// -- Windows 2000 UPN and SID
            KRB5_NT_MS_PRINCIPAL = -128,// -- NT 4 style name
            KRB5_NT_MS_PRINCIPAL_AND_ID = -129,// -- NT style name and SID
            KRB5_NT_NTLM = -1200// -- NTLM name, realm is domain
        }

        private static HashSet<MessageType> REQUEST_TYPES = new HashSet<MessageType>( new[] {
            MessageType.krb_as_req,
            MessageType.krb_tgs_req,
            MessageType.krb_ap_req
        });

        public enum PADataType : ushort {
            NONE = 0,
            TGS_REQ = 1,
            AP_REQ = 1,
            ENC_TIMESTAMP = 2,
            PW_SALT = 3,
            ENC_UNIX_TIME = 5,
            SANDIA_SECUREID = 6,
            SESAME = 7,
            OSF_DCE = 8,
            CYBERSAFE_SECUREID = 9,
            AFS3_SALT = 10,
            ETYPE_INFO = 11,
            SAM_CHALLENGE = 12,// -- (sam/otp)
            SAM_RESPONSE = 13,// -- (sam/otp)
            PK_AS_REQ_19 = 14,// -- (PKINIT-19)
            PK_AS_REP_19 = 15,// -- (PKINIT-19)
            PK_AS_REQ_WIN = 15,// -- (PKINIT - old number)
            PK_AS_REQ = 16,// -- (PKINIT-25)
            PK_AS_REP = 17,// -- (PKINIT-25)
            PA_PK_OCSP_RESPONSE = 18,
            ETYPE_INFO2 = 19,
            USE_SPECIFIED_KVNO = 20,
            SVR_REFERRAL_INFO = 20,// --- old ms referral number
            SAM_REDIRECT = 21,// -- (sam/otp)
            GET_FROM_TYPED_DATA = 22,
            SAM_ETYPE_INFO = 23,
            SERVER_REFERRAL = 25,
            ALT_PRINC = 24,//		-- (crawdad @fnal.gov)
            SAM_CHALLENGE2 = 30,//		-- (kenh @pobox.com)
            SAM_RESPONSE2 = 31,//		-- (kenh @pobox.com)
            EXTRA_TGT = 41,//			-- Reserved extra TGT
            TD_KRB_PRINCIPAL = 102,//	-- PrincipalName
            PK_TD_TRUSTED_CERTIFIERS = 104,// -- PKINIT
            PK_TD_CERTIFICATE_INDEX = 105,// -- PKINIT
            TD_APP_DEFINED_ERROR = 106,//	-- application specific
            TD_REQ_NONCE = 107,//		-- INTEGER
            TD_REQ_SEQ = 108,//		-- INTEGER
            PA_PAC_REQUEST = 128,//	-- jbrezak @exchange.microsoft.com
            FOR_USER = 129,//		-- MS-KILE
            FOR_X509_USER = 130,//		-- MS-KILE
            FOR_CHECK_DUPS = 131,//	-- MS-KILE
            AS_CHECKSUM = 132,//		-- MS-KILE
            PK_AS_09_BINDING = 132,//	-- client send this to
            CLIENT_CANONICALIZED = 133,//	-- referals
            FX_COOKIE = 133,//		-- krb-wg-preauth-framework
            AUTHENTICATION_SET = 134,//	-- krb-wg-preauth-framework
            AUTH_SET_SELECTED = 135,//	-- krb-wg-preauth-framework
            FX_FAST = 136,//		-- krb-wg-preauth-framework
            FX_ERROR = 137,//		-- krb-wg-preauth-framework
            ENCRYPTED_CHALLENGE = 138,//	-- krb-wg-preauth-framework
            OTP_CHALLENGE = 141,//		-- (gareth.richards @rsa.com)
            OTP_REQUEST = 142,//		-- (gareth.richards @rsa.com)
            OTP_CONFIRM = 143,//		-- (gareth.richards @rsa.com)
            OTP_PIN_CHANGE = 144,//	-- (gareth.richards @rsa.com)
            EPAK_AS_REQ = 145,
            EPAK_AS_REP = 146,
            PKINIT_KX = 147,//		-- krb-wg-anon
            PKU2U_NAME = 148,//		-- zhu-pku2u
            REQ_ENC_PA_REP = 149,
            SUPPORTED_ETYPES = 165//   -- MS-KILE
        }


        public List<Tuple<string, Utils.ByteConverter.Asn1TypeTag, byte[]>> AsnData { get; }
        public MessageType MsgType { get; }
        public bool IsRequest {
            get {
                return REQUEST_TYPES.Contains(this.MsgType);
            }
        }

        /*
        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out AbstractPacket result) {

        }
        */

        internal KerberosPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool packetHasLenghtFieldHeader)
        : base(parentFrame, packetStartIndex, packetEndIndex, "Kerberos") {
            int index = packetStartIndex;
            if (packetHasLenghtFieldHeader) {
                int length = (int)(Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex, 4) & 0x7fffff);
                if (packetStartIndex + 4 + length > packetEndIndex + 1)
                    throw new IndexOutOfRangeException("Kerberos packet is truncated");
                base.PacketEndIndex = packetStartIndex + 4 + length - 1;
                index += 4;
            }
            //read ASN.1 data
            this.AsnData = Utils.ByteConverter.GetAsn1Data(parentFrame.Data, ref index, packetEndIndex);
            var firstInts = this.AsnData.Take(2).Where(t => t.Item2 == Utils.ByteConverter.Asn1TypeTag.Integer).Take(2).ToList();
            if (firstInts.Count == 2 && Utils.ByteConverter.ToUInt32(firstInts[0].Item3) == 5) {
                //Kerberos v5
                uint commandType = Utils.ByteConverter.ToUInt32(firstInts[1].Item3);
                if (Enum.IsDefined(typeof(MessageType), (byte)commandType))
                    this.MsgType = (MessageType)commandType;
                else
                    this.MsgType = MessageType.krb_null;
            }
            else
                throw new Exception("Not Kerberos v5");
        }



        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
        }
    }
}
