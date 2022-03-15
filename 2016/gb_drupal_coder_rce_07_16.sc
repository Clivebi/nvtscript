CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105818" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Drupal Coder Remote Code Execution" );
	script_tag( name: "vuldetect", value: "Check for known error message from affected modules" );
	script_tag( name: "insight", value: "The Coder module checks your Drupal code against coding standards and other best practices. It can also fix coding standard violations and perform basic upgrades on modules. The module doesn't sufficiently validate user inputs in a script file that has the php extension. A malicious unauthenticated user can make requests directly to this file to execute arbitrary php code." );
	script_tag( name: "summary", value: "The remote Drupal installation is prone to a remote code execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Install the latest version:" );
	script_xref( name: "URL", value: "https://www.drupal.org/node/2765575" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-07-20 12:15:23 +0200 (Wed, 20 Jul 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "drupal_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "drupal/installed" );
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
url = dir + "/sites/all/modules/coder/coder_upgrade/scripts/coder_upgrade.run.php";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "file parameter is not set" ) || ContainsString( buf, "No path to parameter file" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

