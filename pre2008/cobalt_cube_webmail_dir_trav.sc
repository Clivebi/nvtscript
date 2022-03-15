if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11073" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2001-1408" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "readmsg.php detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 444 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Get a newer software from Cobalt." );
	script_tag( name: "summary", value: "/base/webmail/readmsg.php was detected." );
	script_tag( name: "insight", value: "Some versions of this CGI allow remote users
  to read local files with the permission of the web server.

  Note that if the user has a shell access, this kind of attack is
  not interesting." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://online.securityfocus.com/archive/1/195165" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 444 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/base/webmail/readmsg.php";
if(http_is_cgi_installed_ka( item: url, port: port )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

