if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10302" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "robot(s).txt exists on the Web Server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 1999 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.robotstxt.org/" );
	script_xref( name: "URL", value: "https://www.robotstxt.org/norobots-rfc.txt" );
	script_tag( name: "insight", value: "Any serious web search engine will honor the /robot(s).txt file
  and not scan the files and directories listed there.

  Any entries listed in this file are not even hidden anymore." );
	script_tag( name: "summary", value: "Web Servers can use a file called /robot(s).txt to ask search engines
  to ignore certain files and directories. By nature this file can not be used to protect private files
  from public read access." );
	script_tag( name: "solution", value: "Review the content of the /robot(s).txt file and consider removing the
  files from the server or protect them in other ways in case you actually intended non-public availability." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
for url in make_list( "/robot.txt",
	 "/robots.txt" ) {
	res = http_get_cache( port: port, item: url );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) || !IsMatchRegexp( res, "Content-Type\\s*:\\s*text/plain" )){
		continue;
	}
	body = http_extract_body_from_response( data: res );
	body = chomp( body );
	if(!body){
		continue;
	}
	if(egrep( string: body, pattern: "^\\s*((Dis)?allow|User-agent|Noindex|host|Sitemap|crawl-delay)\\s*:", icase: TRUE )){
		report = NASLString( "The file '", http_report_vuln_url( url: url, port: port, url_only: TRUE ), "' contains the following:\\n", body );
		log_message( port: port, data: report );
	}
}
exit( 0 );

