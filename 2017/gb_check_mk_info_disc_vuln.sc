CPE = "cpe:/a:check_mk_project:check_mk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140449" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-24 14:59:40 +0700 (Tue, 24 Oct 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-17 13:21:00 +0000 (Thu, 17 Oct 2019)" );
	script_cve_id( "CVE-2017-14955" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Check_MK Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_check_mk_web_detect.sc" );
	script_mandatory_keys( "check_mk/detected" );
	script_tag( name: "summary", value: "Check_MK is prone to a race condition vulnerability which could lead to
information disclosure." );
	script_tag( name: "insight", value: "Check_MK mishandles certain errors within the failed-login save feature
because of a race condition, which allows remote attackers to obtain sensitive user information by reading a GUI
crash report." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Check_MK before version 1.2.8p26." );
	script_tag( name: "solution", value: "Update to version 1.2.8p26 or later." );
	script_xref( name: "URL", value: "https://www.rcesecurity.com/2017/10/cve-2017-14955-win-a-race-against-check-mk-to-dump-all-your-login-data/" );
	script_xref( name: "URL", value: "https://mathias-kettner.de/check_mk_werks.php?werk_id=5208&HTML=yes" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.2.8p26" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.8p26" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

