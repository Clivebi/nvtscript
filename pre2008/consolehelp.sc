if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11724" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1518 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2000-0682" );
	script_xref( name: "OSVDB", value: "1481" );
	script_name( "WebLogic source code disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 John Lampe" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA02-03.jsp" );
	script_tag( name: "solution", value: "The vendor has released updates. See the linked advisory for more information." );
	script_tag( name: "summary", value: "There is a bug in the Weblogic web application. Namely,
  by inserting a /ConsoleHelp/ into a URL, critical source code files may be viewed." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
jspfiles = http_get_kb_file_extensions( port: port, host: host, ext: "jsp" );
if( isnull( jspfiles ) ) {
	jspfiles = make_list( "default.jsp" );
}
else {
	jspfiles = make_list( jspfiles );
}
cnt = 0;
for file in jspfiles {
	url = "/ConsoleHelp/" + file;
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<%" ) && ContainsString( res, "%>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	cnt++;
	if(cnt > 10){
		exit( 0 );
	}
}
exit( 99 );

