CPE = "cpe:/a:liferay:liferay_portal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143054" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-10-25 03:29:42 +0000 (Fri, 25 Oct 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-10 20:13:00 +0000 (Thu, 10 Oct 2019)" );
	script_cve_id( "CVE-2019-16891" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Liferay Portal 6.x CE RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_liferay_detect.sc" );
	script_mandatory_keys( "liferay/detected" );
	script_tag( name: "summary", value: "Liferay Portal is prone to a remote code execution vulnerability because of
  deserialization of a JSON payload." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Liferay Portal versions 6.1 GA1 (6.1.10), 6.1 GA2 (6.1.20), 6.1 GA3 (6.1.30),
  6.2 GA1 (6.2.10), 7.0 (7.0.10), 7.1 (7.1.10)." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://issues.liferay.com/browse/LPE-16497" );
	script_xref( name: "URL", value: "https://sec.vnpt.vn/2019/09/liferay-deserialization-json-deserialization-part-4/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "6.1.30.ga3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^6\\.2\\." ) && version_is_less_equal( version: version, test_version: "6.2.10.ga1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7\\.0\\." ) && version_is_less_equal( version: version, test_version: "7.0.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7\\.1\\." ) && version_is_less_equal( version: version, test_version: "7.1.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

