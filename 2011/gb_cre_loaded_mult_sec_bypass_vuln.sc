if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802104" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)" );
	script_cve_id( "CVE-2009-5076", "CVE-2009-5077" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CRE Loaded Multiple Security Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://hosting-4-creloaded.com/node/116" );
	script_xref( name: "URL", value: "https://www.creloaded.com/fdm_file_detail.php?file_id=191" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to bypass authentication and
  gain administrator privileges." );
	script_tag( name: "affected", value: "CRE Loaded version before 6.4.0" );
	script_tag( name: "insight", value: "The flaws are due to

  - An error when handling 'PHP_SELF' variable, by includes/application_top.php
    and admin/includes/application_top.php.

  - Request, with 'login.php' or 'password_forgotten.php' appended as the
    'PATH_INFO', which bypasses a check that uses 'PHP_SELF', which is not
    properly handled by includes/application_top.php and
    admin/includes/application_top.php." );
	script_tag( name: "solution", value: "Upgrade to CRE Loaded version 6.4.0 or later" );
	script_tag( name: "summary", value: "The host is running CRE Loaded and is prone to Security bypass
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.creloaded.com/" );
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
for dir in nasl_make_list_unique( "/cre", "/cre-loaded", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "<title>CRE Loaded" )){
		ver = eregmatch( pattern: "v([0-9.]+)", string: res );
		if(ver != NULL){
			if(version_is_less( version: ver, test_version: "6.4.0" )){
				report = report_fixed_ver( installed_version: ver, fixed_version: "6.4.0" );
				security_message( port: port, data: report );
			}
		}
	}
}
exit( 99 );

