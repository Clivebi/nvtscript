CPE = "cpe:/a:libreoffice:libreoffice";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814905" );
	script_version( "2021-10-04T14:22:38+0000" );
	script_cve_id( "CVE-2018-16858" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-02-07 10:41:49 +0530 (Thu, 07 Feb 2019)" );
	script_name( "LibreOffice RCE Vulnerability (Feb 2019) - Mac OS X" );
	script_tag( name: "summary", value: "LibreOffice is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the file 'pydoc.py' in
  LibreOffice's Python interpreter which accepts and executes arbitrary commands." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and traverse directories." );
	script_tag( name: "affected", value: "LibreOffice before 6.0.7 and 6.1.3." );
	script_tag( name: "solution", value: "Update to version 6.0.7, 6.1.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.libreoffice.org/about-us/security/advisories/cve-2018-16858/" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_libreoffice_detect_macosx.sc" );
	script_mandatory_keys( "LibreOffice/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( version_is_less( version: vers, test_version: "6.0.7" ) ){
	fix = "6.0.7";
}
else {
	if(IsMatchRegexp( vers, "^6.1\\." ) && version_is_less( version: vers, test_version: "6.1.3" )){
		fix = "6.1.3";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

