CPE = "cpe:/a:best_practical_solutions:request_tracker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811527" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_cve_id( "CVE-2017-5944", "CVE-2016-6127", "CVE-2017-5943" );
	script_bugtraq_id( 99381, 99384, 99375 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-07 16:40:00 +0000 (Fri, 07 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-07-18 16:33:24 +0530 (Tue, 18 Jul 2017)" );
	script_name( "Request Tracker Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Request Tracker
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Not using a constant-time comparison algorithm for secrets.

  - It fails to properly validate HTTP requests.

  - Multiple input validation errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application.
  Failed exploits will result in denial-of-service conditions, perform certain
  unauthorized actions and gain access to the affected application and obtain
  sensitive user password information. Other attacks are also possible." );
	script_tag( name: "affected", value: "Request Tracker 4.x before 4.0.25, 4.2.x
  before 4.2.14, and 4.4.x before 4.4.2" );
	script_tag( name: "solution", value: "Upgrade to Request Tracker version 4.0.25 or
  4.2.14 or 4.4.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://forum.bestpractical.com/t/security-vulnerabilities-in-rt-2017-06-15/32016" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "rt_detect.sc" );
	script_mandatory_keys( "RequestTracker/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!rtPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!rtVer = get_app_version( cpe: CPE, port: rtPort )){
	exit( 0 );
}
if(IsMatchRegexp( rtVer, "(^4\\.)" )){
	if( version_is_less( version: rtVer, test_version: "4.0.25" ) ){
		fix = "4.0.25";
	}
	else {
		if( IsMatchRegexp( rtVer, "(^4\\.2)" ) && version_is_less( version: rtVer, test_version: "4.2.14" ) ){
			fix = "4.2.14";
		}
		else {
			if(IsMatchRegexp( rtVer, "(^4\\.4)" ) && version_is_less( version: rtVer, test_version: "4.4.2" )){
				fix = "4.4.2";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: rtVer, fixed_version: fix );
	security_message( port: rtPort, data: report );
	exit( 0 );
}
exit( 0 );

