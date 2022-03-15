CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810585" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 18:43:00 +0000 (Fri, 31 Jul 2020)" );
	script_tag( name: "creation_date", value: "2017-03-09 13:32:59 +0530 (Thu, 09 Mar 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "ImageMagick Multiple Denial of Service Vulnerabilities Mar17 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with ImageMagick
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper processing of PDB file by 'ReadBlobByte' function in
    'coders/pdb.c' script.

  - An error in processing of 'MIFF' file.

  - An error in the 'ReadVICARImage' function in coders/vicar.c script." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to cause a denial of service condition." );
	script_tag( name: "affected", value: "ImageMagick versions 6.x before
  6.9.0-5 Beta on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version
  6.9.0-5 Beta or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/06/06/2" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/02/26/13" );
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
if(IsMatchRegexp( imVer, "^6\\." )){
	if(version_in_range( version: imVer, test_version: "6.0", test_version2: "6.9.0.4" )){
		report = report_fixed_ver( installed_version: imVer, fixed_version: "6.9.0-5 Beta" );
		security_message( data: report );
		exit( 0 );
	}
}

