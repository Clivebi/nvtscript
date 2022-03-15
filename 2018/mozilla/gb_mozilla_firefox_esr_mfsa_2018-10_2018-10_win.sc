CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813058" );
	script_version( "2021-07-01T02:00:36+0000" );
	script_cve_id( "CVE-2018-5148" );
	script_bugtraq_id( 103506 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-09 14:26:00 +0000 (Thu, 09 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-03-27 16:44:32 +0530 (Tue, 27 Mar 2018)" );
	script_name( "Mozilla Firefox ESR Security Updates(mfsa_2018-10_2018-10)-Windows" );
	script_tag( name: "summary", value: "This host is installed with
  Mozilla Firefox ESR and is prone to an use after free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a use after free
  error in the compositor during certain graphics operations when a raw pointer
  is used instead of a reference counted one." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to crash the affected application and denying service to legitimate
  users." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 52.7.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 52.7.3
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-10" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "52.7.3" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "52.7.3", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

