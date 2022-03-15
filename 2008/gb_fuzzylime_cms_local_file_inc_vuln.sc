if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800314" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5291" );
	script_bugtraq_id( 32475 );
	script_name( "fuzzylime cms code/track.php Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32865" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7231" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will cause inclusion and execution of arbitrary
  files from local resources via directory traversal attacks." );
	script_tag( name: "affected", value: "fuzzylime cms version 3.03 and prior." );
	script_tag( name: "insight", value: "The flaw is caused due improper handling of input passed to p parameter
  in code/track.php file when the url, title and excerpt form parameters
  are set to non-null values." );
	script_tag( name: "solution", value: "Update to fuzzylime cms version 3.03a or later." );
	script_tag( name: "summary", value: "The host is running fuzzylime CMS and is prone to Local File
  Inclusion vulnerability." );
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
for path in nasl_make_list_unique( "/fuzzylime/_cms303", http_cgi_dirs( port: port ) ) {
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: path + "/docs/readme.txt", port: port );
	if(!rcvRes){
		continue;
	}
	if(ContainsString( rcvRes, "fuzzylime (cms)" )){
		cmsVer = eregmatch( pattern: "v([0-9.]+)", string: rcvRes );
		if(cmsVer[1] != NULL){
			if(version_is_less_equal( version: cmsVer[1], test_version: "3.03" )){
				report = report_fixed_ver( installed_version: cmsVer[1], vulnerable_range: "Less than or equal to 3.03" );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

