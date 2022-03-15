CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816578" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3744", "CVE-2020-3747", "CVE-2020-3755", "CVE-2020-3742", "CVE-2020-3752", "CVE-2020-3754", "CVE-2020-3743", "CVE-2020-3745", "CVE-2020-3746", "CVE-2020-3748", "CVE-2020-3749", "CVE-2020-3750", "CVE-2020-3751", "CVE-2020-3753", "CVE-2020-3756", "CVE-2020-3762", "CVE-2020-3763" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-26 20:27:00 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-13 11:19:21 +0530 (Thu, 13 Feb 2020)" );
	script_name( "Adobe Reader DC 2015 Security Update (APSB20-05) - Mac OS X" );
	script_tag( name: "summary", value: "Adobe Reader DC (Classic) 2015 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to following
  errors,

  - An out-of-bounds read.

  - Heap overflow.

  - Buffer Error.

  - Use After Free.

  - Stack exhaustion.

  - Privilege Escalation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to sensitive data, execute arbitrary code, gain
  privileged access and memory leak condition." );
	script_tag( name: "affected", value: "Adobe Reader DC 2015 (Classic) prior
  to version 2015.006.30510." );
	script_tag( name: "solution", value: "Update Adobe Reader DC 2015 (Classic) to
  version 2015.006.30510 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb20-05.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(version_in_range( version: vers, test_version: "15.0", test_version2: "15.006.30509" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "15.006.30510 (2015.006.30510)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

