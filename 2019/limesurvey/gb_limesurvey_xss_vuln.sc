CPE = "cpe:/a:limesurvey:limesurvey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141878" );
	script_version( "2021-08-30T09:01:25+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 09:01:25 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-16 17:01:07 +0700 (Wed, 16 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-24 15:42:00 +0000 (Thu, 24 Jan 2019)" );
	script_cve_id( "CVE-2017-18358" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "LimeSurvey < 2.72.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_limesurvey_detect.sc" );
	script_mandatory_keys( "limesurvey/installed" );
	script_tag( name: "summary", value: "LimeSurvey has Stored XSS by using the Continue Later (aka Resume later)
feature to enter an email address, which is mishandled in the admin panel." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 2.72.4 or later." );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2018/limesurvey-persistent-xss-to-code-execution/" );
	script_xref( name: "URL", value: "https://github.com/LimeSurvey/LimeSurvey/commit/700b20e2ae918550bfbf283f433f07622480978b" );
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
if(version_is_less( version: version, test_version: "2.72.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.72.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

