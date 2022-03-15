CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818546" );
	script_version( "2021-09-24T05:06:20+0000" );
	script_cve_id( "CVE-2021-35982", "CVE-2021-39836", "CVE-2021-39837", "CVE-2021-39838", "CVE-2021-39839", "CVE-2021-39840", "CVE-2021-39841", "CVE-2021-39842", "CVE-2021-39843", "CVE-2021-39844", "CVE-2021-39845", "CVE-2021-39846", "CVE-2021-39849", "CVE-2021-39850", "CVE-2021-39851", "CVE-2021-39852", "CVE-2021-39853", "CVE-2021-39854", "CVE-2021-39855", "CVE-2021-39856", "CVE-2021-39857", "CVE-2021-39858", "CVE-2021-39859", "CVE-2021-39860", "CVE-2021-39861", "CVE-2021-39863" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-24 05:06:20 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-17 08:31:02 +0530 (Fri, 17 Sep 2021)" );
	script_name( "Adobe Reader Classic 2020 Security Update (APSB21-55) - Mac OS X" );
	script_tag( name: "summary", value: "The host is missing an important security
  update according to Adobe September update." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.

  - An out-of-bounds write error.

  - A type confusion error.

  - Multiple buffer overflow errors.

  - Multiple null pointer dereference errors.

  - An input validation error.

  - An arbitrary file system read error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service, read arbitrary files and
  disclose sensitive information on vulnerable system." );
	script_tag( name: "affected", value: "Adobe Reader Classic 2020 prior to version
  2020.004.30015 on Mac OS X." );
	script_tag( name: "solution", value: "Update Adobe Reader Classic 2020 to
  version 2020.004.30015 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb21-55.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(version_in_range( version: vers, test_version: "20.0", test_version2: "20.004.30006" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "20.004.30015(2020.004.30015)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

