CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805120" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_cve_id( "CVE-2014-9177" );
	script_bugtraq_id( 71512 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-01-09 12:56:08 +0530 (Fri, 09 Jan 2015)" );
	script_name( "WordPress Html5 Mp3 Player 'playlist.php' Path Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Html5 Mp3 Player with Playlist plugin and is prone to path disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is disclosing installation path or not." );
	script_tag( name: "insight", value: "Flaw is triggered when a remote attacker
  sends a direct request for the /html5plus/playlist.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to discloses the software's installation path resulting in a
  loss of confidentiality." );
	script_tag( name: "affected", value: "WordPress HTML5 MP3 Player with
  Playlist Free plugin before 2.7" );
	script_tag( name: "solution", value: "Upgrade to version 2.7 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/98988" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129286" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/html5-mp3-player-with-playlist/changelog" );
	script_xref( name: "URL", value: "http://h4x0resec.blogspot.in/2014/11/wordpress-html5-mp3-player-with.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
url = dir + "/wp-content/plugins/html5-mp3-player-with-playlist/html5plus/playlist.php";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<b>Fatal error</b>:  Call to a member function get_row\\(\\)", extra_check: make_list( "on line <b>18</b>",
	 "html5plus/playlist.php" ) )){
	security_message( port: http_port );
	exit( 0 );
}

