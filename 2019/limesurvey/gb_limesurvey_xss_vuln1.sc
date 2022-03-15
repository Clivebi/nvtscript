CPE = "cpe:/a:limesurvey:limesurvey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141880" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-16 17:07:47 +0700 (Wed, 16 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-18 15:25:00 +0000 (Mon, 18 Mar 2019)" );
	script_cve_id( "CVE-2018-20322" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "LimeSurvey < 3.15.6 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_limesurvey_detect.sc" );
	script_mandatory_keys( "limesurvey/installed" );
	script_tag( name: "summary", value: "LimeSurvey contains an XSS vulnerability while uploading a ZIP file, resulting
in JavaScript code execution against LimeSurvey admins." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 3.15.6 or later." );
	script_xref( name: "URL", value: "https://github.com/LimeSurvey/LimeSurvey/commit/bfee69edaa0b90f97dc2d8fab09a87958cb32405" );
	script_xref( name: "URL", value: "https://bugs.limesurvey.org/view.php?id=14376" );
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
if(version_is_less( version: version, test_version: "3.15.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.15.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

