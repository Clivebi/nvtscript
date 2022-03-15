if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10711" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 3091, 3092 );
	script_cve_id( "CVE-2001-1010" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Sambar webserver pagecount hole" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Vincent Renardias" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sambar_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sambar_server/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/199410" );
	script_tag( name: "solution", value: "Remove this script." );
	script_tag( name: "summary", value: "By default, there is a pagecount script with Sambar Web Server
  located at http://sambarserver/session/pagecount.

  This counter writes its temporary files in c:\\sambardirectory\\tmp.
  It allows to overwrite any files on the filesystem since the 'page'
  parameter is not checked against '../../' attacks." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/session/pagecount";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( res, "HTTP/1\\.. 404" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

