if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113411" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-19 12:35:34 +0000 (Wed, 19 Jun 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-12730" );
	script_name( "FFmpeg < 3.2.14 Use Of Uninitialized Variables" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ffmpeg_detect_lin.sc" );
	script_mandatory_keys( "FFmpeg/Linux/Ver" );
	script_tag( name: "summary", value: "FFmpeg does not check for sscanf failure and consequently allows use of uninitialized variables." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker to execute arbitrary code on the target machine." );
	script_tag( name: "affected", value: "FFmpeg through version 3.2.13." );
	script_tag( name: "solution", value: "Update to version 3.2.14." );
	script_xref( name: "URL", value: "https://github.com/FFmpeg/FFmpeg/commit/ed188f6dcdf0935c939ed813cf8745d50742014b" );
	exit( 0 );
}
CPE = "cpe:/a:ffmpeg:ffmpeg";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "3.2.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.14", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

