CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810297" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2016-10060", "CVE-2016-10061", "CVE-2016-10062" );
	script_bugtraq_id( 95208, 95207, 95209 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-28 19:20:00 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-01-17 15:22:25 +0530 (Tue, 17 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "ImageMagick Multiple Security Bypass Vulnerabilities (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with ImageMagick
  and is prone to multiple security bypass vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  fwrite issues and some other unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to bypass certain security restrictions to perform unauthorized
  actions. This may aid in further attacks." );
	script_tag( name: "affected", value: "ImageMagick versions before 7.0.1-10
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version
  7.0.1-10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2016/q4/758" );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/commit/933e96f01a8c889c7bf5ffd30020e86a02a046e7" );
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
if(version_is_less( version: imVer, test_version: "7.0.1.10" )){
	report = report_fixed_ver( installed_version: imVer, fixed_version: "7.0.1-10" );
	security_message( data: report );
	exit( 0 );
}

