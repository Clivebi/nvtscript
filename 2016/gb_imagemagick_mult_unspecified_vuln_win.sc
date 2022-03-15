CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810247" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5689" );
	script_bugtraq_id( 91283 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-16 14:14:00 +0000 (Fri, 16 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "ImageMagick Multiple Unspecified Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "The host is installed with ImageMagick
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in ReadDCMImage function in DCM reader in computing the
    pixel scaling table.

  - The lack of validation of pixel.red, pixel.green and pixel.blue by DCM reader.

  - The lack of NULL pointer checks by DCM reader." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to cause some unspecified impacts." );
	script_tag( name: "affected", value: "ImageMagick versions before 6.9.4-5 and
  7.x before 7.0.1-7 on Windows." );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version
  6.9.4-5 or 7.0.1-7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://blog.fuzzing-project.org/46-Various-invalid-memory-reads-in-ImageMagick-WPG,-DDS,-DCM.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_imagemagick_detect_win.sc" );
	script_mandatory_keys( "ImageMagick/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!imVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( version_is_less( version: imVer, test_version: "6.9.4.5" ) ){
	fix = "6.9.4-5";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( imVer, "^7\\." )){
		if(version_is_less( version: imVer, test_version: "7.0.1.7" )){
			fix = "7.0.1-7";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: imVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

