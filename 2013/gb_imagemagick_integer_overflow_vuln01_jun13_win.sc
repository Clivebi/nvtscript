CPE = "cpe:/a:imagemagick:imagemagick";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803814" );
	script_version( "2021-07-02T02:00:36+0000" );
	script_cve_id( "CVE-2012-1185" );
	script_bugtraq_id( 51957 );
	script_tag( name: "last_modification", value: "2021-07-02 02:00:36 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-06-24 11:06:50 +0530 (Mon, 24 Jun 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 18:39:00 +0000 (Fri, 31 Jul 2020)" );
	script_name( "ImageMagick Integer Overflow Vulnerability - 01 June13 (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/76140" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2012/03/19/5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_imagemagick_detect_win.sc" );
	script_mandatory_keys( "ImageMagick/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow a context-dependent attacker to cause
  denial of service condition or potentially execute arbitrary code." );
	script_tag( name: "affected", value: "ImageMagick version 6.7.5 and earlier on Windows." );
	script_tag( name: "insight", value: "Integer overflow error occurs due to an improper sanitation of user supplied
  input when computing the sum of 'number_bytes' and 'offset' in
  magick/profile.c or magick/property.c with a specially crafted request." );
	script_tag( name: "solution", value: "Upgrade to ImageMagick version 6.7.5-1 or later." );
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
if(version_is_less( version: vers, test_version: "6.7.5.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.7.5.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

