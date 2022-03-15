CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810502" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_cve_id( "CVE-2016-10053", "CVE-2016-10054", "CVE-2016-10055", "CVE-2016-10056", "CVE-2016-10057" );
	script_bugtraq_id( 95179, 95191, 95193, 95190, 95192 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 19:55:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-01-17 15:28:04 +0530 (Tue, 17 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "ImageMagick Multiple Denial of Service Vulnerabilities Jan17 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with ImageMagick
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to multiple buffer overflow
  errors in files 'coders/map.c', 'coders/pdb.c', 'coders/sixel.c' and
  'coders/tiff.c' and an unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to cause denial-of-service condition." );
	script_tag( name: "affected", value: "ImageMagick versions before 6.9.5-8
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version
  6.9.5-8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2016/q4/758" );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/commit/f983dcdf9c178e0cbc49608a78713c5669aa1bb5" );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/commit/10b3823a7619ed22d42764733eb052c4159bc8c1" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_imagemagick_detect_macosx.sc" );
	script_mandatory_keys( "ImageMagick/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!imVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: imVer, test_version: "6.9.5.8" )){
	report = report_fixed_ver( installed_version: imVer, fixed_version: "6.9.5-8" );
	security_message( data: report );
	exit( 0 );
}

