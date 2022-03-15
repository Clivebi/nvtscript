CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108140" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-18 08:00:00 +0200 (Tue, 18 Apr 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 19:15:00 +0000 (Fri, 18 Sep 2020)" );
	script_cve_id( "CVE-2017-7615" );
	script_name( "MantisBT Pre-Auth Remote Password Reset Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mantisbt/detected" );
	script_xref( name: "URL", value: "http://hyp3rlinx.altervista.org/advisories/MANTIS-BUG-TRACKER-PRE-AUTH-REMOTE-PASSWORD-RESET.txt" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=22690" );
	script_tag( name: "summary", value: "This host is installed with MantisBT which is prone to a remote password reset vulnerability." );
	script_tag( name: "insight", value: "The flaw exists because MantisBT allows arbitrary password reset and unauthenticated admin access
  via an empty confirm_hash value to verify.php." );
	script_tag( name: "vuldetect", value: "Check if it is possible to reset an admin/user password." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote unauthenticated attacker to reset an admin/user password." );
	script_tag( name: "affected", value: "MantisBT versions 1.3.x before 1.3.10 and 2.3.0." );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.3.10, 2.3.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/verify.php?id=1&confirm_hash=";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<form id=\"account-update-form\" method=\"post\" action=\"account_update.php\">" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

