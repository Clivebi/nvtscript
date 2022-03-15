CPE = "cpe:/a:osticket:osticket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13648" );
	script_version( "2020-05-12T10:26:19+0000" );
	script_tag( name: "last_modification", value: "2020-05-12 10:26:19 +0000 (Tue, 12 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2004-0613" );
	script_bugtraq_id( 10586 );
	script_name( "osTicket Attachment Viewing Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Web application abuses" );
	script_dependencies( "osticket_detect.sc", "no404.sc" );
	script_mandatory_keys( "osticket/installed" );
	script_tag( name: "solution", value: "Upgrade to osTicket STS 1.2.7 or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of osTicket that enables a
  remote user to view attachments associated with any existing ticket.

  These attachments may contain sensitive information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_no404_string( port: port, host: host )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/attachments/";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ereg( pattern: "^HTTP/1\\.[01] 200", string: res, icase: TRUE ) && ContainsString( res, "[DIR]" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

