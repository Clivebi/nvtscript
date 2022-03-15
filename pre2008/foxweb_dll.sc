if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11939" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 8547 );
	script_cve_id( "CVE-2010-1898" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "foxweb CGI" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Remove it from /cgi-bin or upgrade it." );
	script_tag( name: "summary", value: "The foxweb.dll or foxweb.exe CGI is installed.

  Versions 2.5 and below of this CGI program have a security flaw
  that lets an attacker execute arbitrary code on the remote server." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for cgi in make_list( "foxweb.dll",
	 "foxweb.exe" ) {
	res = http_is_cgi_installed_ka( item: cgi, port: port );
	if(res){
		report = http_report_vuln_url( port: port, url: "/" + cgi );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

