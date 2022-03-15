CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818106" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_cve_id( "CVE-2021-29945" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-30 19:01:00 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-20 16:16:42 +0530 (Tue, 20 Apr 2021)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2021-13_2021-16) - 01 - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the WebAssembly JIT could
  miscalculate the size of a return type." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause denial of service." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 88 on
  Windows x86-32 platforms." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox version 88
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-16/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!os_arch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
if(!ContainsString( os_arch, "x86" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "88" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "88", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

