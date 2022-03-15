if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11657" );
	script_version( "2021-05-18T07:55:59+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 07:55:59 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Synchrologic Email Accelerator User Account Information Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2003 John Lampe" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Synchrologic Email Accelerator is prone to an information
  disclosure vulnerability." );
	script_tag( name: "impact", value: "The server allows anonymous users to look at Top Network user
  IDs.

  Example : http://example.com/en/admin/aggregate.asp" );
	script_tag( name: "solution", value: "If this server is on an Internet segment (as opposed to
  internal), you may wish to tighten the access to the aggregate.asp page." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
url = "/en/admin/aggregate.asp";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "/css/rsg_admin_nav.css" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

