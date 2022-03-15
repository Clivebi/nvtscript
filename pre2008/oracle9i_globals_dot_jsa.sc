CPE = "cpe:/a:oracle:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10850" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4034 );
	script_cve_id( "CVE-2002-0562" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Oracle 9iAS Globals.jsa access" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_app_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "oracle/http_server/detected" );
	script_xref( name: "URL", value: "http://www.nextgenss.com/advisories/orajsa.txt" );
	script_tag( name: "solution", value: "Edit httpd.conf to disallow access to *.jsa." );
	script_tag( name: "summary", value: "In the default configuration of Oracle9iAS, it is possible to make
  requests for the globals.jsa file for a given web application.

  These files should not be returned by the server as they often contain sensitive information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/demo/ojspext/events/globals.jsa";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "event:application_OnStart" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

