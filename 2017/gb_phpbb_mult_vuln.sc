CPE = "cpe:/a:phpbb:phpbb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140291" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-10 16:43:53 +0700 (Thu, 10 Aug 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-16 18:12:00 +0000 (Tue, 16 Jan 2018)" );
	script_cve_id( "CVE-2017-1000419" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "phpBB < 3.1.11, 3.2.x < 3.2.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phpbb_detect.sc" );
	script_mandatory_keys( "phpBB/installed" );
	script_tag( name: "summary", value: "phpBB is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "phpBB is prone to multiple vulnerabilities:

  - Server-side request forgery (SSRF) vulnerability in the remote avatar functionality which could be used to
  perform service discovery on internal and external networks as well as retrieve images which are usually
  restricted to local access. (CVE-2017-1000419)

  - Cross-site scripting vulnerability via version check files." );
	script_tag( name: "affected", value: "phpBB versions prior to 3.1.11 and version 3.2.0." );
	script_tag( name: "solution", value: "Update to version 3.1.11/3.2.1 or later." );
	script_xref( name: "URL", value: "https://www.phpbb.com/community/viewtopic.php?f=14&t=2430891" );
	script_xref( name: "URL", value: "https://www.phpbb.com/community/viewtopic.php?f=14&t=2430926" );
	script_xref( name: "URL", value: "https://www.sec-consult.com/en/Vulnerability-Lab/Advisories.htm" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.1.11" )){
	fix = "3.1.11";
}
if(IsMatchRegexp( version, "^3\\.2\\." )){
	if(version_is_less( version: version, test_version: "3.2.1" )){
		fix = "3.2.1";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

