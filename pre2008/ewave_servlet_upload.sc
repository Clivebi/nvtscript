if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10570" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1876 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_cve_id( "CVE-2000-1024" );
	script_name( "Unify eWave ServletExec 3.0C file upload" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "summary", value: "ServletExec has a servlet called 'UploadServlet' in its server
  side classes. UploadServlet, when invocable, allows an attacker to upload any file to any directory
  on the server. The uploaded file may have code that can later be executed on the server,
  leading to remote command execution." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
res = http_is_cgi_installed_ka( item: "/servlet/vt-test." + NASLString( rand(), rand(), rand() ), port: port );
if(res){
	exit( 0 );
}
url = "/servlet/com.unify.servletexec.UploadServlet";
res = http_is_cgi_installed_ka( item: url, port: port );
if(res){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
}

