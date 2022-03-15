CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804231" );
	script_version( "2021-08-04T10:08:11+0000" );
	script_cve_id( "CVE-2014-1242" );
	script_bugtraq_id( 65088 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-01-30 16:38:39 +0530 (Thu, 30 Jan 2014)" );
	script_name( "Apple iTunes Tutorials Window Security Bypass Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes and is prone to security bypass
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to iTunes Tutorials window, which uses a non-secure HTTP
  connection to retrieve content." );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker to perform man-in-the-middle
  attacks and obtain sensitive information." );
	script_tag( name: "affected", value: "Apple iTunes before 11.1.4 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 11.1.4 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/90653" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_itunes_detect_macosx.sc" );
	script_mandatory_keys( "Apple/iTunes/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "11.1.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.1.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

