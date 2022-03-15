CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818109" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_cve_id( "CVE-2021-29951" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-30 19:33:00 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-05 10:32:36 +0530 (Wed, 05 May 2021)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa_2021-18_2021-19) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to Mozilla maintenance service
  could have been started or stopped by domain users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to start or stop the service. This could be used to prevent the browser update
  service from operating." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 78.10.1
  on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR version
  78.10.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-18/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1, win2016: 1, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	sysPath = smb_get_system32root();
	if(!sysPath){
		exit( 0 );
	}
	edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
	if(!edgeVer){
		exit( 0 );
	}
	if(!IsMatchRegexp( edgeVer, "^11\\.0\\.1[0123456]" )){
		exit( 0 );
	}
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "78.10.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "78.10.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

