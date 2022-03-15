CPE = "cpe:/a:atutor:atutor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19587" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-2649" );
	script_bugtraq_id( 14598 );
	script_xref( name: "OSVDB", value: "18842" );
	script_xref( name: "OSVDB", value: "18843" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ATutor Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "gb_atutor_detect.sc", "cross_site_scripting.sc" );
	script_mandatory_keys( "atutor/detected" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2005-08/0261.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0600.html" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another
  one." );
	script_tag( name: "summary", value: "The remote version of ATutor is prone to cross-site scripting
  attacks due to its failure to sanitize user-supplied input." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("url_func.inc.sc");
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
xss = "<script>alert(" + vtstrings["lowercase_rand"] + ")</script>";
exss = urlencode( str: xss );
host = http_host_name( port: port );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
url = dir + "/login.php?course=\">" + exss;
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, xss ) && egrep( string: res, pattern: "Web site engine's code is copyright .+ href=.http://www\\.atutor\\.ca" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );
