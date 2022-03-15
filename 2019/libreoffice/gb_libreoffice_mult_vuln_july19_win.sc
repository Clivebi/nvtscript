CPE = "cpe:/a:libreoffice:libreoffice";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815422" );
	script_version( "2021-10-04T14:22:38+0000" );
	script_cve_id( "CVE-2019-9848", "CVE-2019-9849" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-15 18:15:00 +0000 (Thu, 15 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-07-19 17:12:56 +0530 (Fri, 19 Jul 2019)" );
	script_name( "LibreOffice Multiple Vulnerabilities (Jul 2019) - Windows" );
	script_tag( name: "summary", value: "LibreOffice is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper validation for user supplied input when document event feature
    trigger LibreLogo to execute python contained within a document.

  - Remote bullet graphics were omitted from stealth mode protection." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary python commands silently without warning and retrieve
  remote resources from untrusted locations." );
	script_tag( name: "affected", value: "LibreOffice prior to 6.2.5." );
	script_tag( name: "solution", value: "Update to version 6.2.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.libreoffice.org/about-us/security/advisories/cve-2019-9848/" );
	script_xref( name: "URL", value: "https://www.libreoffice.org/about-us/security/advisories/cve-2019-9849/" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_libreoffice_detect_portable_win.sc" );
	script_mandatory_keys( "LibreOffice/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "6.2.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.2.5", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

