CPE = "cpe:/a:cubecart:cubecart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17227" );
	script_version( "2021-05-17T11:26:07+0000" );
	script_bugtraq_id( 12549 );
	script_cve_id( "CVE-2005-0442", "CVE-2005-0443" );
	script_tag( name: "last_modification", value: "2021-05-17 11:26:07 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Brooky CubeCart index.php language XSS Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cubecart_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cubecart/installed" );
	script_tag( name: "summary", value: "CubeCart is vulnerable to cross-site scripting (XSS) and remote
  script injection due to a lack of sanitization of user-supplied data." );
	script_tag( name: "impact", value: "Successful exploitation of this issue may allow an attacker to
  execute malicious script code on a vulnerable server." );
	script_tag( name: "solution", value: "Update to version 2.0.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
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
	vtstrings = get_vt_strings();
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/upload/index.php?&language=<script>", vtstrings["lowercase"], "-xss-test</script>" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>" + vtstrings["lowercase"] + "-xss-test</script>", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
ver = infos["version"];
if(!ver){
	exit( 0 );
}
if(version_is_less_equal( version: ver, test_version: "2.0.4" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.0.5", install_url: dir );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

