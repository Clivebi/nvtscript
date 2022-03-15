CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816811" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3804", "CVE-2020-3806", "CVE-2020-3795", "CVE-2020-3799", "CVE-2020-3792", "CVE-2020-3793", "CVE-2020-3801", "CVE-2020-3802", "CVE-2020-3805", "CVE-2020-3800", "CVE-2020-3807", "CVE-2020-3797", "CVE-2020-3803" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-27 14:24:00 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-18 10:10:57 +0530 (Wed, 18 Mar 2020)" );
	script_name( "Adobe Reader DC (Continuous) Security Update (APSB20-13) - Windows" );
	script_tag( name: "summary", value: "Adobe Reader DC is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to following
  errors,

  - An out-of-bounds read.

  - An out-of-bounds write.

  - A stack-based buffer overflow.

  - An use-after-free.

  - Memory address leak.

  - Buffer overflow.

  - Memory corruption.

  - Insecure library loading (DLL hijacking)." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to sensitive information, gain escalated privileges
  and execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Reader DC 2020 (Continuous)
  versions before 2020.006.20042." );
	script_tag( name: "solution", value: "Update Adobe Reader DC (Continuous)
  to version 2020.006.20042 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb20-13.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_reader_dc_cont_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/ReaderDC/Continuous/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "20.0", test_version2: "20.006.20041" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "20.006.20042 (2020.006.20042)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

