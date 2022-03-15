if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10816" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3473 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0835" );
	script_name( "Webalizer Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Alert4Web.com" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to Version 2.01-09 and change the directory in 'OutputDir'." );
	script_tag( name: "summary", value: "Webalizer have a cross-site scripting vulnerability,
  that could allow malicious HTML tags to be injected in the reports generated by the Webalizer." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
dirs = make_list( "/usage/",
	 "/webalizer/" );
port = http_get_port( default: 80 );
for dir in dirs {
	buf = http_get_cache( item: dir, port: port );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "Generated by The Webalizer" ) && egrep( pattern: "Generated by The Webalizer  Ver(\\.|sion) ([01]\\.|2\\.00|2\\.01( |\\-0[0-6]))", string: buf )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

