CPE = "cpe:/a:zoneminder:zoneminder";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106521" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-17 13:28:38 +0700 (Tue, 17 Jan 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-16 01:59:00 +0000 (Thu, 16 Mar 2017)" );
	script_cve_id( "CVE-2016-10140" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "ZoneMinder Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zoneminder_detect.sc" );
	script_mandatory_keys( "zoneminder/installed" );
	script_tag( name: "summary", value: "ZoneMinder is prone to an information disclosure and authentication
bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to get a directory listing on the /events/ folder." );
	script_tag( name: "insight", value: "Information disclosure and authentication bypass vulnerability exists in
the Apache HTTP Server configuration bundled with ZoneMinder, which allows a remote unauthenticated attacker to
browse all directories in the web root, e.g., a remote unauthenticated attacker can view all CCTV images on the
server." );
	script_tag( name: "impact", value: "An unauthenticated remote attacker may browse all directories in the web
root." );
	script_tag( name: "solution", value: "Disable directory listings in the apache configuration." );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/ZoneMinder/pull/1697" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
if(http_vuln_check( port: port, url: dir + "/events/", pattern: "<title>Index of.*/events</title>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: dir + "/events/" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

