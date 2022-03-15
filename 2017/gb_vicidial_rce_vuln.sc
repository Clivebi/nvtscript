CPE = "cpe:/a:vicidial:vicidial";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106838" );
	script_version( "2021-06-16T14:43:08+0000" );
	script_tag( name: "last_modification", value: "2021-06-16 14:43:08 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-05-30 10:12:02 +0700 (Tue, 30 May 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "VICIdial Remote OS Command Execution Vulnerability (May 2017)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_vicidial_detect.sc" );
	script_mandatory_keys( "vicidial/http/detected" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "VICIdial is prone to a remote OS command execution
  vulnerability." );
	script_tag( name: "insight", value: "VICIdial versions 2.9 RC1 to 2.13 RC1 allows unauthenticated
  users to execute arbitrary operating system commands as the web server user if password
  encryption is enabled (disabled by default)." );
	script_tag( name: "impact", value: "An unauthenticated attacker may execute arbitrary OS commands as
  the web server." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP request and checks if input filtering is
  not patched and if password encryption is supported which indicates that the server is vulnerable." );
	script_tag( name: "solution", value: "See the referenced link for a solution." );
	script_xref( name: "URL", value: "http://www.vicidial.org/VICIDIALmantis/view.php?id=1016" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
user = rand_str( length: 10, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz" );
pass = "#" + rand_str( length: 10, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz" ) + "&#";
userpass = user + ":" + pass;
userpass64 = base64( str: userpass );
authstr = "Basic " + userpass64;
req = http_get_req( port: port, url: "/vicidial/vicidial_sales_viewer.php", add_headers: make_array( "Authorization", authstr ) );
res = http_keepalive_send_recv( port: port, data: req );
if(!eregmatch( pattern: "\\|" + user + "\\|" + pass + "\\|BAD\\|", string: res )){
	exit( 99 );
}
if(http_vuln_check( port: port, url: "/agc/bp.pl", pattern: "Bcrypt password hashing script", check_header: TRUE )){
	report = "Result of the check:\nInput filtering is not patched and password encryption is supported. " + "Which indicates that the server is vulnerable if password encryption is enabled.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

