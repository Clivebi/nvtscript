if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10670" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "PHP3 Physical Path Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://online.securityfocus.com/archive/1/65078" );
	script_xref( name: "URL", value: "http://online.securityfocus.com/archive/101/184240" );
	script_tag( name: "solution", value: "In the PHP configuration file change display_errors to 'Off':

  display_errors = Off" );
	script_tag( name: "summary", value: "PHP3 will reveal the physical path of the webroot when asked for
  a non-existent PHP3 file if it is incorrectly configured." );
	script_tag( name: "insight", value: "Although printing errors to the output is useful for debugging
  applications, this feature should not be enabled on production servers." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/nosuchfile-10303-10310.php3";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "Unable to open" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

