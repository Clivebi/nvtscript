CPE = "cpe:/a:invision_power_services:invision_power_board";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12648" );
	script_version( "$Revision: 11556 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 17:37:40 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "SQL Disclosure in Invision Power Board" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "invision_power_board_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "invision_power_board/installed" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "summary", value: "There is a vulnerability in the current version of Invision Power Board
that allows an attacker to reveal the SQL queries used by the product, and
any page that was built by the administrator using the IPB's interface,
simply by appending the variable 'debug' to the request." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
port = get_app_port( cpe: CPE );
if(!port){
	exit( 0 );
}
if(!path = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = http_get( item: NASLString( path, "/?debug=whatever" ), port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(res == NULL){
	exit( 0 );
}
find = NASLString( "SQL Debugger" );
find2 = NASLString( "Total SQL Time" );
find3 = NASLString( "mySQL time" );
if(ContainsString( res, find ) || ContainsString( res, find2 ) || ContainsString( res, find3 )){
	security_message( port );
	exit( 0 );
}

