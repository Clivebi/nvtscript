if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10415" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "Sambar sendmail /session/sendmail" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Hendrik Scholz" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sambar_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sambar_server/detected" );
	script_tag( name: "solution", value: "Try to disable this module. There might be a patch in the future." );
	script_tag( name: "summary", value: "The Sambar webserver is running. It provides a web interface for sending emails.
  You may simply pass a POST request to /session/sendmail and by this send mails to anyone you want.
  Due to the fact that Sambar does not check HTTP referrers you do not need direct access to the server!" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
url = "/session/sendmail";
if(http_is_cgi_installed_ka( port: port, item: url )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

