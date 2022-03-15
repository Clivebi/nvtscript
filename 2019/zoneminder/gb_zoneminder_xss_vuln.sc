CPE = "cpe:/a:zoneminder:zoneminder";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141929" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-01-28 12:57:55 +0700 (Mon, 28 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-24 20:14:00 +0000 (Thu, 24 Jan 2019)" );
	script_cve_id( "CVE-2019-6777" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ZoneMinder 1.32.3 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zoneminder_detect.sc" );
	script_mandatory_keys( "zoneminder/installed" );
	script_tag( name: "summary", value: "An issue was discovered in ZoneMinder v1.32.3. Reflected XSS exists in
  web/skins/classic/views/plugin.php via the zm/index.php?view=plugin pl parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the provided patch." );
	script_xref( name: "URL", value: "https://github.com/ZoneMinder/zoneminder/issues/2436" );
	script_xref( name: "URL", value: "https://github.com/mnoorenberghe/ZoneMinder/commit/59cc65411f02c7e39a270fda3ecb4966d7b48d41" );
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
if(version_is_equal( version: version, test_version: "1.32.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply patch." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

