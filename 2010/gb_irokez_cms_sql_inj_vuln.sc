if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801445" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)" );
	script_cve_id( "CVE-2009-4982" );
	script_bugtraq_id( 35957 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Irokez CMS 'id' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/23497" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2167" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw is caused by an input validation error in the 'select()'
  function when processing the 'id' parameter, which could be exploited by
  malicious people to conduct SQL injection attacks." );
	script_tag( name: "solution", value: "Upgrade to version 0.8b or later." );
	script_tag( name: "summary", value: "This host is running Irokez CMS and is prone SQL injection
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to access or modify
  data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Irokez CMS version 0.7.1 and prior" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.irokez.org/download/cms" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
cmsPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/irokez", "/cms", "/", http_cgi_dirs( port: cmsPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/ru/" ), port: cmsPort );
	rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
	if(ContainsString( rcvRes, "<title>Irokez" )){
		sndReq = http_get( item: NASLString( dir, "/ru/news/7'" ), port: cmsPort );
		rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
		if(ContainsString( rcvRes, "You have an error" ) && ContainsString( rcvRes, "syntax" )){
			security_message( port: cmsPort );
			exit( 0 );
		}
	}
}
exit( 99 );

