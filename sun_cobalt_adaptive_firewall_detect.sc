if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10878" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Sun Cobalt Adaptive Firewall Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecurITeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8181 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Access to this port (by default set to port 8181) should not be permitted from
  the outside. Further access to the firewall interface itself should not be allowed (by default set to port 2005)." );
	script_tag( name: "summary", value: "Sun Cobalt machines contain a firewall mechanism, this mechanism can be
  configured remotely by accessing Cobalt's built-in HTTP server. Upon access to the HTTP server, a java
  based administration program would start, where a user is required to enter a pass phrase in order to
  authenticate himself. Since no username is required, just a passphrase bruteforcing of this interface is
  easier." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8181 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "Sun Cobalt Adaptive Firewall" ) && ContainsString( buf, "One moment please" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		http_set_is_marked_embedded( port: port );
		exit( 0 );
	}
}
exit( 99 );

