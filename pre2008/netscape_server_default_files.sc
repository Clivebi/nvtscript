if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12077" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Netscape Enterprise Server default files " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Kyger" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Netscape Enterprise Server has default files installed.

  Default files were found on the Netscape Enterprise Server." );
	script_tag( name: "solution", value: "These files should be removed as they may help an attacker to guess the
  exact version of the Netscape Server which is running on this host." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
report = "The following default files were found:\n";
port = http_get_port( default: 80 );
for file in make_list( "/help/contents.htm",
	 "/manual/ag/contents.htm" ) {
	buf = http_get_cache( item: file, port: port );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "Netscape Enterprise Server Administrator's Guide" ) || ContainsString( buf, "Enterprise Edition Administrator's Guide" ) || ContainsString( buf, "Netshare and Web Publisher User's Guide" )){
		report += "\n" + file;
		vuln = TRUE;
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

