if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18364" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 13722 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Sambar Server Administrative Interface multiple XSS" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_dependencies( "gb_sambar_server_detect.sc", "cross_site_scripting.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sambar_server/detected" );
	script_tag( name: "solution", value: "Upgrade at least to version 6.2.1." );
	script_tag( name: "summary", value: "The remote host runs the Sambar web server.

  The remote version of this software is vulnerable to multiple cross site
  scripting attacks.

  With a specially crafted URL, an attacker can use the remote host to perform
  a cross site scripting against a third party." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/search/results.stm?indexname=>\"><script>foo</script>&style=fancy&spage=60&query=Folder%20name" );
	if(http_vuln_check( port: port, url: url, pattern: ">S</FONT>AMBAR", extra_check: "<script>foo</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

