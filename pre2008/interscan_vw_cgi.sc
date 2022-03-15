if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10733" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2579 );
	script_cve_id( "CVE-2001-0432" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "InterScan VirusWall Remote Configuration Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 INTRANODE" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Don't connect the management interface directly to the Internet." );
	script_tag( name: "summary", value: "The management interface used with the Interscan VirusWall
  uses several cgi programs that may allow a malicious user to remotely change the configuration
  of the server without any authorization using maliciously constructed querystrings." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/interscan/cgi-bin/FtpSave.dll?I'm%20Here";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "These settings have been saved" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

