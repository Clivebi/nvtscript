CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803817" );
	script_version( "2021-07-05T02:00:48+0000" );
	script_cve_id( "CVE-2012-1610" );
	script_bugtraq_id( 52898 );
	script_tag( name: "last_modification", value: "2021-07-05 02:00:48 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-06-24 13:28:50 +0530 (Mon, 24 Jun 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-14 18:47:00 +0000 (Fri, 14 Aug 2020)" );
	script_name( "ImageMagick Integer Overflow Vulnerability - 02 June13 (Windows)" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2012/q2/19" );
	script_xref( name: "URL", value: "http://www.cert.fi/en/reports/2012/vulnerability635606.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_imagemagick_detect_win.sc" );
	script_mandatory_keys( "ImageMagick/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to cause denial of service
  condition result in loss of availability for the application." );
	script_tag( name: "affected", value: "ImageMagick version before 6.7.6-4 on Windows." );
	script_tag( name: "insight", value: "Integer overflow error occurs due to improper sanitation of user supplied
  input when by a crafted JPEG EXIF tag with an excessive components count
  to the 'GetEXIFProperty()' and 'SyncImageProfiles()' functions in
  magick/profile.c" );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version 6.7.6-4 or later." );
	script_tag( name: "summary", value: "The host is installed with ImageMagick and is prone to integer
  overflow Vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "6.7.6.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.7.6.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

