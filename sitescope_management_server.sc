if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10740" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "SiteScope Web Managegment Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8888 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Disable the SiteScope Management web server if it is unnecessary,
  or block incoming traffic to this port." );
	script_tag( name: "summary", value: "The remote web server is running the SiteScope Management
  web server." );
	script_tag( name: "impact", value: "This service allows attackers to gain sensitive information on
  the SiteScope-monitored server.

  Sensitive information includes (but is not limited to): license number,
  current users, administrative email addresses, database username and
  password, SNMP community names, UNIX usernames and passwords,
  LDAP configuration, access to internal servers (via Diagnostic tools), etc." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
for url in make_list( "/SiteScope/htdocs/SiteScope.html",
	 "/" ) {
	res = http_get_cache( item: url, port: port );
	if( ContainsString( res, "Freshwater Software" ) && ContainsString( res, "URL=SiteScope.html" ) ){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	else {
		if(ContainsString( res, "URL=/SiteScope/htdocs/SiteScope.html" ) && ContainsString( res, "A HREF=/SiteScope/htdocs/SiteScope.html" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			http_set_is_marked_embedded( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

