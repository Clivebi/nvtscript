CPE = "cpe:/a:unitrends:backup";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140250" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-12 16:05:50 +0200 (Wed, 12 Apr 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-7280", "CVE-2017-7284", "CVE-2017-7281", "CVE-2017-7279", "CVE-2017-7282", "CVE-2017-7283" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Unitrends < 9.1.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_unitrends_http_detect.sc" );
	script_mandatory_keys( "unitrends/detected" );
	script_tag( name: "summary", value: "Unitrends is  prone to multiple vulnerabilities:

  - RCE in /api/includes/systems.php Unitrends < 9.0.0

  - Forced Password Change Unitrends in /api/includes/users.php < 9.1.2

  - Unrestricted File Upload

  - Privilege Escalation in Unitrends < 9.0.0" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Unitrends prior to version 9.1.2." );
	script_tag( name: "solution", value: "Update to version 9.1.2 or later." );
	script_xref( name: "URL", value: "https://rhinosecuritylabs.com/research/remote-code-execution-bug-hunting-chapter-1/" );
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
if(version_is_less( version: version, test_version: "9.1.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

