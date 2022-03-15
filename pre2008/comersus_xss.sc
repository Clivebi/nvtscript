if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12640" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0681", "CVE-2004-0682" );
	script_bugtraq_id( 10674 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Comersus Cart Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to version 5.098 or newer" );
	script_tag( name: "summary", value: "The malicious user is able to compromise the parameters to invoke a
  Cross-Site Scripting attack. This can be used to take advantage of the trust between a client and
  server allowing the malicious user to execute malicious JavaScript on the client's machine or perform
  a denial of service shutting down IIS." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/comersus/store", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: NASLString( dir, "/comersus_message.asp?message=vttest<script>foo</script>" ), port: port );
	r = http_keepalive_send_recv( port: port, data: req );
	if(isnull( r )){
		continue;
	}
	if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && ContainsString( r, "<font size=\"2\">vttest<script>foo</script>" )){
		security_message( port );
		exit( 0 );
	}
}
exit( 99 );

