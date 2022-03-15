if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113462" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-14 14:03:54 +0000 (Wed, 14 Aug 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-14 13:29:00 +0000 (Tue, 14 May 2019)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-10649", "CVE-2019-10650" );
	script_bugtraq_id( 107645, 107646 );
	script_name( "ImageMagick <= 7.0.8-36 Multiple Vulnerabilities (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_imagemagick_detect_macosx.sc" );
	script_mandatory_keys( "ImageMagick/MacOSX/Version" );
	script_tag( name: "summary", value: "ImageMagick is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - There is a memory leak in the function SVGKeyValuePairs of coders/svg.c
    which allows an attacker to cause a denial of service
    via a crafted image file.

  - There is a heap-based buffer over-read in the function WriteTIFFImage
    of coders/tiff.c which allows an attacker to cause a denial of service
    or information disclosure via a crafted image file." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to read sensitive information
  or crash the application." );
	script_tag( name: "affected", value: "ImageMagick through version 7.0.8-36." );
	script_tag( name: "solution", value: "Update to version 7.0.8-37." );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/issues/1533" );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/issues/1532" );
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
if(version_is_less( version: version, test_version: "7.0.8.37" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.8-37", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

