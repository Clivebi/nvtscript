CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803600" );
	script_version( "$Revision: 11865 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-05-14 12:10:16 +0530 (Tue, 14 May 2013)" );
	script_name( "WordPress Xili Language Plugin XSS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53364" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/53364" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "WordPress Xili Language Plugin version 2.8.4.3 and prior" );
	script_tag( name: "insight", value: "The input passed via 'lang' parameter to index.php script is not properly
  validated." );
	script_tag( name: "solution", value: "Update to Xili Language Plugin version 2.8.5 or later." );
	script_tag( name: "summary", value: "This host is running WordPress with Xili Language plugin and is
  prone to cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/xili-language" );
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
url = dir + "/?lang=%22><script>alert(12345)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(12345\\)</script>" )){
	security_message( port: port );
	exit( 0 );
}

