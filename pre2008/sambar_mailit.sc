if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10417" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Sambar /cgi-bin/mailit.pl installed ?" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Hendrik Scholz" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sambar_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sambar_server/detected" );
	script_tag( name: "solution", value: "Remove it from /cgi-bin." );
	script_tag( name: "summary", value: "The Sambar webserver is running
  and the 'mailit.pl' cgi is installed. This CGI takes
  a POST request from any host and sends a mail to a supplied address." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
url = "/cgi-bin/mailit.pl";
if(http_is_cgi_installed_ka( item: url, port: port )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

