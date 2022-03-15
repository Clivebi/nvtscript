CPE = "cpe:/a:qnap:video_station";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146085" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-07 04:54:53 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 17:34:00 +0000 (Fri, 11 Jun 2021)" );
	script_cve_id( "CVE-2021-28812" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS Video Station Command Injection Vulnerability (QSA-21-21)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_videostation_http_detect.sc" );
	script_mandatory_keys( "qnap/videostation/detected" );
	script_tag( name: "summary", value: "QNAP Video Station is prone to a command injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "If exploited, this vulnerability allows remote attackers to execute
  arbitrary commands." );
	script_tag( name: "affected", value: "QNAP Music Station versions prior to 5.5.4 (QTS 4.5.2)." );
	script_tag( name: "solution", value: "Update to version 5.5.4 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/qsa-21-21" );
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
if(version_in_range( version: version, test_version: "5.4.0", test_version2: "5.5.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

