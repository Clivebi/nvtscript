CPE = "cpe:/a:qnap:photo_station";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146819" );
	script_version( "2021-10-06T08:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-10-04 07:18:38 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-10-04 15:51:00 +0000 (Mon, 04 Oct 2021)" );
	script_cve_id( "CVE-2021-34355" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP NAS Photo Station XSS Vulnerability (QSA-21-42)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_photo_station_detect.sc" );
	script_mandatory_keys( "QNAP/QTS/PhotoStation/detected" );
	script_tag( name: "summary", value: "QNAP NAS Photo Station is prone to a stored cross-site
  scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "impact", value: "If exploited, this vulnerability allows remote attackers to
  inject malicious code." );
	script_tag( name: "affected", value: "QNAP Photo Station prior to version 5.4.10, 5.7.13 or 6.0.18." );
	script_tag( name: "solution", value: "Update to version 5.4.10, 5.7.13, 6.0.18 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/qsa-21-42" );
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
if(version_is_less( version: version, test_version: "5.4.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.4.10" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.6", test_version2: "5.7.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.13" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0", test_version2: "6.0.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.18" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

