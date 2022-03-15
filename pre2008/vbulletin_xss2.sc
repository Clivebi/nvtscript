CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14833" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2004-1824" );
	script_bugtraq_id( 6226 );
	script_xref( name: "OSVDB", value: "3280" );
	script_name( "vBulletin XSS(2)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "cross_site_scripting.sc", "vbulletin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "solution", value: "Upgrade to latest version." );
	script_tag( name: "summary", value: "The remote version of vBulletin seems to be prior
  or equal to version 2.2.9. These versions are vulnerable to a cross-site scripting issue,
  due to a failure of the application to properly sanitize user-supplied URI input." );
	script_tag( name: "impact", value: "As a result of this vulnerability, it is possible for
  a remote attacker to create a malicious link containing script code that will be executed
  in the browser of an unsuspecting user when followed.

  This may facilitate the theft of cookie-based authentication credentials
  as well as other attacks." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
url = dir + "/memberlist.php?s=23c37cf1af5d2ad05f49361b0407ad9e&what=<script>vt-test</script>";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>vt-test</script>", string: res )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

