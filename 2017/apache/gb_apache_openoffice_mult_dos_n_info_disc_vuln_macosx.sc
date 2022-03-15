CPE = "cpe:/a:openoffice:openoffice.org";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812227" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2017-9806", "CVE-2017-3157", "CVE-2017-12608", "CVE-2017-12607" );
	script_bugtraq_id( 101585, 96402 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-05 13:23:00 +0000 (Tue, 05 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-11-27 19:44:19 +0530 (Mon, 27 Nov 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Apache OpenOffice Multiple DoS And Information Disclosure Vulnerabilities (MAC OS X)" );
	script_tag( name: "summary", value: "The host is installed with Apache OpenOffice
  and is prone to multiple denial of service and information disclosure
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the WW8Fonts Constructor in the OpenOffice Writer DOC file parser.

  - An error in rendering embedded objects.

  - An error in the ImportOldFormatStyles in Apache OpenOffice Writer DOC file parser.

  - An error in the OpenOffice's PPT file parser in PPTStyleSheet." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause denial of service (memory corruption and application crash)
  potentially resulting in arbitrary code execution and to retrieve sensitive
  information." );
	script_tag( name: "affected", value: "Apache OpenOffice before 4.1.4 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Apache OpenOffice 4.1.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.openoffice.org/security/cves/CVE-2017-9806.html" );
	script_xref( name: "URL", value: "https://www.openoffice.org/security/cves/CVE-2017-3157.html" );
	script_xref( name: "URL", value: "https://www.openoffice.org/security/cves/CVE-2017-12608.html" );
	script_xref( name: "URL", value: "https://www.openoffice.org/security/cves/CVE-2017-12607.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_openoffice_detect_macosx.sc" );
	script_mandatory_keys( "OpenOffice/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
openoffcVer = infos["version"];
openoffcpath = infos["location"];
if(version_is_less( version: openoffcVer, test_version: "4.1.4" )){
	report = report_fixed_ver( installed_version: openoffcVer, fixed_version: "4.1.4", install_path: openoffcpath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

