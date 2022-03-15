if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10996" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1386 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2000-0539" );
	script_name( "JRun Sample Files" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Digital Defense Inc." );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Sample files should never be left on production
  servers.  Remove the sample files and any other files that are not required." );
	script_tag( name: "summary", value: "This host is running the Allaire JRun web server
  and has sample files installed." );
	script_tag( name: "impact", value: "Several of the sample files that come with JRun contain serious
  security flaws. An attacker can use these scripts to relay web requests from this machine to
  another one or view sensitive configuration information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
tests = make_array( "/cfanywhere/index.html", "CFML Sample", "/docs/servlets/index.html", "JRun Servlet Engine", "/jsp/index.html", "JRun Scripting Examples", "/webl/index.html", "What is WebL" );
port = http_get_port( default: 80 );
for url in keys( tests ) {
	check = tests[url];
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( data: req, port: port );
	if(!res){
		continue;
	}
	if(ContainsString( res, check )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

