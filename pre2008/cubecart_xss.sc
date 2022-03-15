CPE = "cpe:/a:cubecart:cubecart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19945" );
	script_version( "2021-01-11T10:44:01+0000" );
	script_cve_id( "CVE-2005-3152" );
	script_bugtraq_id( 14962 );
	script_tag( name: "last_modification", value: "2021-01-11 10:44:01 +0000 (Mon, 11 Jan 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Multiple CubeCart Multiple XSS Vulnerabilities" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "secpod_cubecart_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cubecart/installed" );
	script_xref( name: "URL", value: "http://lostmon.blogspot.com/2005/09/cubecart-303-multiple-variable-cross.html" );
	script_tag( name: "solution", value: "Upgrade to CubeCart version 3.0.4 or later." );
	script_tag( name: "summary", value: "The remote version of CubeCart contains several cross-site scripting
  vulnerabilities due to its failure to properly sanitize user-supplied input of certain variables to
  the 'index.php' and 'cart.php' scripts." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("url_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
if(!dir = infos["location"]){
	dir = "/";
}
if(!safe_checks()){
	if(dir == "/"){
		dir = "";
	}
	vtstrings = get_vt_strings();
	xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
	exss = urlencode( str: xss );
	url = NASLString( dir, "/upload/index.php?", "searchStr=\">", exss, "&act=viewCat&Submit=Go" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, xss )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
ver = infos["version"];
if(!ver){
	exit( 0 );
}
if(version_is_less_equal( version: ver, test_version: "3.0.3" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "3.0.4", install_url: dir );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

