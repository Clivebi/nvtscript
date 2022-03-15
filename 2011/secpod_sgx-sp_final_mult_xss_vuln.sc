if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902532" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)" );
	script_cve_id( "CVE-2010-3926" );
	script_bugtraq_id( 45752 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "SGX-SP Final 'shop.cgi' Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://wb-i.net/soft1.HTML#spf" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42857" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64593" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "SGX-SP Final version 10.0 and prior." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input passed to
  shop.cgi, which allows attackers to execute arbitrary HTML and script code
  in a user's browser session in context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to SGX-SP Final version 11.0 or later." );
	script_tag( name: "summary", value: "This host is running SGX-SP Final and is prone to multiple cross
  site scripting vulnerabilities." );
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
for dir in nasl_make_list_unique( "/SPF", "/shop", "/mall", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/shop.cgi", port: port );
	ver = eregmatch( pattern: "SGX-SPF Ver([0-9.]+)", string: res );
	if(ver[1]){
		if(version_is_less( version: ver[1], test_version: "11.00" )){
			report = report_fixed_ver( installed_version: ver[1], fixed_version: "11.00" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

