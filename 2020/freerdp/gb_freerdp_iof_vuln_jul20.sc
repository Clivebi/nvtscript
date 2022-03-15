if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113735" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-07-29 12:23:26 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-23 18:34:00 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-15103" );
	script_name( "FreeRDP < 2.2.0 Integer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_freerdp_detect_lin.sc" );
	script_mandatory_keys( "FreeRDP/Linux/Ver" );
	script_tag( name: "summary", value: "FreeRDP is prone to an integer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists due to missing input sanitation in rdpegfx channel." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash the application." );
	script_tag( name: "affected", value: "FreeRDP through version 2.1.2." );
	script_tag( name: "solution", value: "Update to version 2.2.0." );
	script_xref( name: "URL", value: "https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-4r38-6hq7-j3j9" );
	exit( 0 );
}
CPE = "cpe:/a:freerdp_project:freerdp";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

