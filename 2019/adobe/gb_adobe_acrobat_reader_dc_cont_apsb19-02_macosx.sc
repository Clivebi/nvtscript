CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814804" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_cve_id( "CVE-2018-16011", "CVE-2018-16018" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-01-04 11:35:03 +0530 (Fri, 04 Jan 2019)" );
	script_name( "Adobe Acrobat Reader DC (Continuous Track) Security Updates (apsb19-02) - Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat
  Reader DC (Continuous Track) and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use after free error.

  - Security bypass error." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to conduct arbitrary code execution in the context of the current
  user and escalate privileges." );
	script_tag( name: "affected", value: "Adobe Acrobat Reader DC (Continuous Track)
  2019.010.20064 and earlier versions on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat Reader DC Continuous
  version 2019.010.20069 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb19-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_reader_dc_cont_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Acrobat/ReaderDC/Continuous/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "19.010.20069" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "19.010.20069 (2019.010.20069)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

