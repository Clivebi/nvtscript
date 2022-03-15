if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902066" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)" );
	script_cve_id( "CVE-2010-2114" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "Brekeke PBX Cross-Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39952" );
	script_xref( name: "URL", value: "http://cross-site-scripting.blogspot.com/2010/05/brekeke-pbx-2448-cross-site-request.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 28080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw exists in the application which fails to perform
  validity checks on certain 'HTTP reqests', which allows an attacker to hijack
  the authentication of users for requests that change passwords via the
  pbxadmin.web.PbxUserEdit bean." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Brekeke PBX version 2.4.6.7 or later." );
	script_tag( name: "summary", value: "This host is running Brekeke PBX and is prone to Cross-Site
  Request Forgery Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to change the
  administrator's password by tricking a logged in administrator into visiting a
  malicious web site." );
	script_tag( name: "affected", value: "Brekeke PBX version 2.4.4.8." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 28080 );
req = http_get( item: NASLString( "/pbx/gate?bean=pbxadmin.web.PbxLogin" ), port: port );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, ">Brekeke PBX<" )){
	version = eregmatch( pattern: "Version ([0-9.]+)", string: res );
	if(version[1] != NULL){
		if(version_is_less_equal( version: version[1], test_version: "2.4.4.8" )){
			report = report_fixed_ver( installed_version: version[1], vulnerable_range: "Less or equal to 2.4.4.8" );
			security_message( port: port, data: report );
		}
	}
}

