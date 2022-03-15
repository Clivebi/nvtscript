CPE = "cpe:/a:qnap:music_station";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145025" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-12-11 04:25:50 +0000 (Fri, 11 Dec 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 16:57:00 +0000 (Mon, 21 Jun 2021)" );
	script_cve_id( "CVE-2020-2494" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS Music Station XSS Vulnerability (QSA-20-13)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_musicstation_detect.sc" );
	script_mandatory_keys( "qnap_musicstation/detected" );
	script_tag( name: "summary", value: "QNAP Music Station is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "This cross-site scripting vulnerability in Music Station allows remote
  attackers to inject malicious code." );
	script_tag( name: "affected", value: "QNAP Music Station versions prior to 5.3.12." );
	script_tag( name: "solution", value: "Update to version 5.3.12 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/qsa-20-13" );
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
if(version_is_less( version: version, test_version: "5.3.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

