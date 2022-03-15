CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804788" );
	script_version( "2019-11-12T13:33:43+0000" );
	script_cve_id( "CVE-2014-8584" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-11-12 13:33:43 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2014-11-07 16:00:58 +0530 (Fri, 07 Nov 2014)" );
	script_name( "WordPress Web Dorado Spider Video Player XSS Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Web Dorado Spider Video Player plugin and is prone to cross-site scripting
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'TrackId', 'task', and 'id'
  GET parameters are not properly sanitized before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Web Dorado Spider Video Player
  version before 1.5.2" );
	script_tag( name: "solution", value: "Update to version 1.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/player/changelog" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-admin/admin-ajax.php?action=spiderVeideoPlayersettingsxml" + "&playlist=1&theme=6&s_v_player_id=<script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "playlistBtnHint" )){
	security_message( port: http_port );
	exit( 0 );
}

