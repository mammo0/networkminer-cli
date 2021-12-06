namespace PacketParser.FileTransfer {
    public enum FileStreamTypes {
        //FtpActiveRetr,
        //FtpActiveStor,
        //FtpPassiveRetr,
        //FtpPassiveStor,
        FTP,
        HttpGetChunked,
        HttpGetNormal,
        HttpPost,
        HttpPostMimeMultipartFormData,
        HttpPostMimeFileData,
        HttpPostUpload,
        HTTP2,
        IMAP,
        LPD,
        OscarFileTransfer,
        POP3,
        RTP,
        SMB,
        SMB2,
        SMTP,
        TFTP,
        TlsCertificate
    }
}