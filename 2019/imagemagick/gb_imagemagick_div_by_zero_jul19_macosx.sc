if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113431" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-15 11:30:32 +0000 (Mon, 15 Jul 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-19 18:58:00 +0000 (Wed, 19 Aug 2020)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-13454" );
	script_bugtraq_id( 109099 );
	script_name( "ImageMagick < 7.0.8-54 Division By Zero Error (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_imagemagick_detect_macosx.sc" );
	script_mandatory_keys( "ImageMagick/MacOSX/Version" );
	script_tag( name: "summary", value: "ImageMagick is prone to a division by zero error." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists within RemoveDuplicateLayers in MagickCore/layer.c." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash the application." );
	script_tag( name: "affected", value: "ImageMagick version 7.0.8-53 and prior." );
	script_tag( name: "solution", value: "Update to version 7.0.8-54 or later." );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/issues/1629" );
	exit( 0 );
}
CPE = "cpe:/a:imagemagick:imagemagick";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "7.0.8.54" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.8.54", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

