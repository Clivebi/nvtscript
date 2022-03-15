if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10956" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-1999-0739" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Codebrws.asp Source Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Matt Moore / HD Moore" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/banner" );
	script_tag( name: "solution", value: "Remove the /IISSamples virtual directory using the Internet Services Manager.

  If for some reason this is not possible, removing the following ASP script will fix the problem:

  This path assumes that you installed IIS in c:\\inetpub

  c:\\inetpub\\iissamples\\sdk\\asp\\docs\\CodeBrws.asp" );
	script_tag( name: "summary", value: "Microsoft's IIS 5.0 web server is shipped with a set of
  sample files to demonstrate different features of the ASP language. One of these sample
  files allows a remote user to view the source of any file in the web root with the extension
  .asp, .inc, .htm, or .html." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
sig = http_get_remote_headers( port: port );
if(!sig || !ContainsString( sig, "IIS" )){
	exit( 0 );
}
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
url = "/iissamples/sdk/asp/docs/codebrws.asp";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( data: req, port: port );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "View Active Server Page Source" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

