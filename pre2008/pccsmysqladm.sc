if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10783" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1557 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2000-0707" );
	script_category( ACT_GATHER_INFO );
	script_name( "PCCS-Mysql User/Password Exposure" );
	script_copyright( "Copyright (C) 2001 Alert4Web.com" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Versions 1.2.5 and later are not vulnerable to this issue.
  A workaround is to restrict access to the .inc file." );
	script_tag( name: "summary", value: "It is possible to read the include file of PCCS-Mysql,
  dbconnect.inc on the remote server.

  This include file contains information such as the username and password used to connect to
  the database." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
cgi = "/pccsmysqladm/incs/dbconnect.inc";
res = http_is_cgi_installed_ka( port: port, item: cgi );
if(res){
	report = http_report_vuln_url( port: port, url: cgi );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

