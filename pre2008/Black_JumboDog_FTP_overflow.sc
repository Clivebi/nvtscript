if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14256" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1439" );
	script_bugtraq_id( 10834 );
	script_xref( name: "OSVDB", value: "8273" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "BlackJumboDog FTP server multiple command overflow" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/blackjumbodog/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 3.6.2 or newer." );
	script_tag( name: "summary", value: "The remote host is running BlackJumboDog FTP server.

  This FTP server fails to properly check the length of parameters
  in multiple FTP commands, most significant of which is USER, resulting in a stack overflow." );
	script_tag( name: "impact", value: "With a specially crafted request, an attacker can execute arbitrary code
  resulting in a loss of integrity, and/or availability." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "BlackJumboDog" )){
	if( safe_checks() ){
		if(egrep( pattern: "^220 .*BlackJumboDog.* Version 3\\.([0-5]\\.[0-9]+|6\\.[01])", string: banner )){
			security_message( port );
		}
	}
	else {
		req1 = NASLString( "USER ", crap( 300 ), "\\r\\n" );
		soc = open_sock_tcp( port );
		if(!soc){
			exit( 0 );
		}
		send( socket: soc, data: req1 );
		close( soc );
		sleep( 1 );
		soc2 = open_sock_tcp( port );
		if( !soc2 || !ftp_recv_line( socket: soc ) ){
			security_message( port );
		}
		else {
			close( soc2 );
		}
		exit( 0 );
	}
}

