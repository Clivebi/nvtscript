if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113113" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-15 13:34:44 +0100 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-6930" );
	script_name( "ImageMagick 7.0.7.22 DoS Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_imagemagick_detect_lin.sc" );
	script_mandatory_keys( "ImageMagick/Lin/Ver" );
	script_tag( name: "summary", value: "ImageMagick is prone to a Denial of Service vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A stack-based buffer over-read in the ComputeResizeImage function in the MagickCore/accelerate.c file of ImageMagick 7.0.7-22 allows a remote attacker to cause a denial of service (application crash) via a maliciously crafted pict file." );
	script_tag( name: "affected", value: "ImageMagick through version 7.0.7.22." );
	script_tag( name: "solution", value: "Update to version 7.0.2.23 or later." );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/issues/967" );
	exit( 0 );
}
CPE = "cpe:/a:imagemagick:imagemagick";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "7.0.7.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.7.23" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

