if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802207" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)" );
	script_cve_id( "CVE-2011-1584" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Dotclear Arbitrary File Upload Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44049" );
	script_xref( name: "URL", value: "http://dev.dotclear.org/2.0/changeset/2:3427" );
	script_xref( name: "URL", value: "http://dotclear.org/blog/post/2011/04/01/Dotclear-2.2.3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation allows remote authenticated users to upload and
  execute arbitrary PHP code." );
	script_tag( name: "affected", value: "Dotclear versions prior to 2.2.3." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input passed
  via the 'updateFile()' function in inc/core/class.dc.media.php, which
  allows attackers to execute arbitrary PHP code by uploading a PHP file." );
	script_tag( name: "solution", value: "Upgrade to Dotclear version 2.2.3 or later." );
	script_tag( name: "summary", value: "This host is running Dotclear and is prone to arbitrary file upload
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://dotclear.org/download" );
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
for dir in nasl_make_list_unique( "/dotclear", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(egrep( pattern: "Powered by.*>Dotclear<", string: res )){
		req = http_get( item: dir + "/CHANGELOG", port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		ver = eregmatch( pattern: "Dotclear ([0-9.]+)", string: res );
		if(ver[1] == NULL){
			exit( 0 );
		}
		if(version_is_less( version: ver[1], test_version: "2.2.3" )){
			report = report_fixed_ver( installed_version: ver[1], fixed_version: "2.2.3" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

