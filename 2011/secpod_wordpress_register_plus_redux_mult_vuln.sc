CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902656" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-30 15:11:51 +0530 (Fri, 30 Dec 2011)" );
	script_name( "WordPress Register Plus Redux Plugin Multiple Vulnerabilities" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/5532/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45503/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosiure/2011/Dec/489" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108235/registerplus3731-xss.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site or obtain sensitive information." );
	script_tag( name: "affected", value: "WordPress Register Plus Redux Plugin 3.7.3.1 and prior." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Improper validation of input passed to 'wp-login.php' script (when
    'action' is set to 'register').

  - A direct request to 'dashboard_invitation_tracking_widget.php' and
    'register-plus-redux.php' allows remote attackers to obtain installation
    path in error message." );
	script_tag( name: "solution", value: "Upgrade to WordPress Register Plus Redux Plugin version 3.8 or later." );
	script_tag( name: "summary", value: "The host is running WordPress Register Plus Redux Plugin and is
  prone to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/register-plus-redux/" );
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
if(dir == "/"){
	dir = "";
}
url = dir + "/wp-content/plugins/register-plus-redux/register-plus-redux.php";
if(http_vuln_check( port: port, url: url, pattern: "<b>Fatal error</b>:  ?Call to undefined function.*register-plus-redux\\.php" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

