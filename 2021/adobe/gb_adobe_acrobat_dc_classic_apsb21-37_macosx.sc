CPE = "cpe:/a:adobe:acrobat_dc_classic";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818151" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-28554", "CVE-2021-28551", "CVE-2021-28552", "CVE-2021-28631", "CVE-2021-28632" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 14:09:00 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 14:56:45 +0530 (Thu, 10 Jun 2021)" );
	script_name( "Adobe Acrobat Classic 2020 Security Update (APSB21-37) - Mac OS X" );
	script_tag( name: "summary", value: "Adobe Acrobat Classic 2020 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code on vulnerable system." );
	script_tag( name: "affected", value: "Adobe Acrobat Classic 2020 prior to version
  2020.004.30005 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat Classic 2020 version
  2020.004.30005 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb21-37.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_dc_classic_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/AcrobatDC/Classic/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "20.0", test_version2: "20.001.30025" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "20.004.30005(2020.004.30005)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

