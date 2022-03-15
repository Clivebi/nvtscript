CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810281" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2016-10068" );
	script_bugtraq_id( 95219 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-01-16 15:59:02 +0530 (Mon, 16 Jan 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "ImageMagick MSL Interpreter Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with ImageMagick
  and is prone to denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the failure to handle
  exceptional conditions by MSL interpreter." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to cause a denial-of-service condition." );
	script_tag( name: "affected", value: "ImageMagick versions before 6.9.6-4
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version
  6.9.6-4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2016/q4/758" );
	script_xref( name: "URL", value: "https://github.com/ImageMagick/ImageMagick/commit/56d6e20de489113617cbbddaf41e92600a34db22" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_imagemagick_detect_win.sc" );
	script_mandatory_keys( "ImageMagick/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!imVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: imVer, test_version: "6.9.6.4" )){
	report = report_fixed_ver( installed_version: imVer, fixed_version: "6.9.6-4" );
	security_message( data: report );
	exit( 0 );
}

