CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813859" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-12808", "CVE-2018-12799" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-08-16 11:03:52 +0530 (Thu, 16 Aug 2018)" );
	script_name( "Adobe Acrobat Reader DC (Classic Track) Multiple Arbitrary Code Execution Vulnerabilities (apsb18-29) - Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat Reader
  DC (Classic Track) and is prone to multiple arbitrary code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An untrusted pointer dereference error.

  - An out-of-bounds write error." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to conduct arbitrary code execution in the context of the current
  user." );
	script_tag( name: "affected", value: "Adobe Acrobat Reader DC (Classic Track)
  2015.006.30434 and earlier versions on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat Reader DC (Classic Track)
  version 2015.006.30448 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb18-29.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_reader_dc_classic_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Acrobat/ReaderDC/Classic/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "15.006.30448" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "15.006.30448 (2015.006.30448)", install_path: path );
	security_message( data: report );
	exit( 0 );
}

