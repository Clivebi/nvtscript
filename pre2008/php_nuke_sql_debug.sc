CPE = "cpe:/a:phpnuke:php-nuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10856" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-2032" );
	script_bugtraq_id( 3906 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "PHP-Nuke sql_debug Information Disclosure" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2002 Alert4Web.com" );
	script_dependencies( "secpod_php_nuke_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "php-nuke/installed" );
	script_tag( name: "solution", value: "Add '$sql_debug = 0<semicolon>' in config.php." );
	script_tag( name: "summary", value: "In PHP-Nuke, the sql_layer.php script contains a debugging
  feature that may be used by attackers to disclose sensitive information about all SQL queries.
  Access to the debugging feature is not restricted to administrators." );
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
url = dir + "/?sql_debug=1";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "SQL query: " )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

