CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902327" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-01-03 16:00:43 +0100 (Mon, 03 Jan 2011)" );
	script_cve_id( "CVE-2010-4637" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress FeedList Plugin 'i' Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42197" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/63055" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/WordPress.Feed.List.2.61.01.Reflected.Cross-site.Scripting/56" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of an affected
site." );
	script_tag( name: "affected", value: "WordPress FeedList plugin version 2.61.01" );
	script_tag( name: "insight", value: "The flaw is due to an input passed to 'i' parameter in
'wp-content/plugins/feedlist/handler_image.php' script is not properly
sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress and is prone to Cross Site Scripting
vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
wpPort = get_app_port( cpe: CPE );
if(!wpPort){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: wpPort )){
	exit( 0 );
}
if(dir != NULL){
	sndReq = http_get( item: NASLString( dir, "/wp-content/plugins/feedlist/handler_image.php" + "?i=%3Cscript%3Ealert(\"XSS-Testing\")%3C/script%3E" ), port: wpPort );
	rcvRes = http_keepalive_send_recv( port: wpPort, data: sndReq );
	if(IsMatchRegexp( rcvRes, "HTTP/1\\.. 200" ) && ContainsString( rcvRes, "Cached file for <script>alert(\"XSS-Testing\")</script> cannot be found" )){
		security_message( wpPort );
	}
}

