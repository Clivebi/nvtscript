if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800312" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-12-05 15:00:57 +0100 (Fri, 05 Dec 2008)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5296" );
	script_bugtraq_id( 32440 );
	script_name( "Gallery Unspecified Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32817" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/46804" );
	script_xref( name: "URL", value: "http://gallery.menalto.com/last_official_G1_releases" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to bypass authentication and gain
  administrative access to the application, if register_globals is enabled." );
	script_tag( name: "affected", value: "Gallery Version 1.5.x before 1.5.10 and 1.6 before 1.6-RC3 on all
  platform." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of authentication cookies." );
	script_tag( name: "solution", value: "Update to version 1.5.10 or 1.6-RC3." );
	script_tag( name: "summary", value: "The host is running Gallery and is prone to Security Bypass
  Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/gallery", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(!rcvRes){
		continue;
	}
	if(ContainsString( rcvRes, "Powered by Gallery" )){
		gallVer = eregmatch( pattern: "([0-9.]+)(-[A-Z0-9]+)? -", string: rcvRes );
		gallVer = ereg_replace( pattern: " -", string: gallVer[0], replace: "" );
		gallVer = ereg_replace( pattern: "-", string: gallVer, replace: "." );
		if(gallVer != NULL){
			if(IsMatchRegexp( gallVer, "^1\\.5" ) && version_in_range( version: gallVer, test_version: "1.5", test_version2: "1.5.9" )){
				security_message( port: port );
				exit( 0 );
			}
			if(IsMatchRegexp( gallVer, "^1\\.6" ) && version_in_range( version: gallVer, test_version: "1.6", test_version2: "1.6.RC2" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

