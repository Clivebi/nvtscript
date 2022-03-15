if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800143" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5191" );
	script_bugtraq_id( 29996 );
	script_name( "SePortal poll.php SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/30865" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/5960" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary SQL queries." );
	script_tag( name: "affected", value: "SePortal Version 2.4 and prior on all running platform." );
	script_tag( name: "insight", value: "Input passed to the poll_id parameter in poll.php and to sp_id parameter
  in staticpages.php files are not properly sanitised before being used in an SQL query." );
	script_tag( name: "solution", value: "Upgrade to SePortal Version 2.5 or later" );
	script_tag( name: "summary", value: "The host is running SePortal which is prone to SQL Injection
  Vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/seportal", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir + "/index.php" ), port: port );
	if(!rcvRes){
		continue;
	}
	if(ContainsString( rcvRes, "SePortal<" )){
		sepVer = eregmatch( string: rcvRes, pattern: "SePortal<.+ ([0-9]\\.[0-9.]+)" );
		if(sepVer[1] != NULL){
			if(version_is_less_equal( version: sepVer[1], test_version: "2.4" )){
				report = report_fixed_ver( installed_version: sepVer[1], vulnerable_range: "Less than or equal to 2.4" );
				security_message( port: port, data: report );
			}
		}
		exit( 0 );
	}
}
exit( 99 );

