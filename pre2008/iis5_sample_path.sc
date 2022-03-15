if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10573" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "IIS 5.0 Sample App reveals physical path of web root" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Matt Moore" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Always remove sample applications from productions servers.
  In this case, remove the entire /iissamples folder." );
	script_tag( name: "summary", value: "A sample application shipped with IIS 5.0 discloses
  the physical path of the web root. An attacker can use this information
  to make more focused attacks." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
cgi = "/iissamples/sdk/asp/interaction/ServerVariables_Jscript.asp";
res = http_is_cgi_installed_ka( item: cgi, port: port );
if(res){
	report = http_report_vuln_url( port: port, url: cgi );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

