CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810505" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2016-10046", "CVE-2016-10051" );
	script_bugtraq_id( 95183, 95187 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 19:57:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-01-17 15:33:11 +0530 (Tue, 17 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "ImageMagick Buffer Overflow And Use-after-free Vulnerabilities (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with ImageMagick
  and is prone to an use-after-free and buffer overflow vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The failure to adequately bounds-check user-supplied data before copying it to an
    insufficiently sized memory buffer.

  - An use-after-free error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary code within the context of the application.
  Failed exploit attempts will likely cause a denial-of-service condition." );
	script_tag( name: "affected", value: "ImageMagick versions before 6.9.5-5
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version
  6.9.5-5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2016/q4/758" );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/commit/ecc03a2518c2b7dd375fde3a040fdae0bdf6a521" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_imagemagick_detect_macosx.sc" );
	script_mandatory_keys( "ImageMagick/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!imVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: imVer, test_version: "6.9.5.5" )){
	report = report_fixed_ver( installed_version: imVer, fixed_version: "6.9.5-5" );
	security_message( data: report );
	exit( 0 );
}

