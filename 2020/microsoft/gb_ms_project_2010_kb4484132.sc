CPE = "cpe:/a:microsoft:project";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816887" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-0760" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-17 19:11:00 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-16 14:00:17 +0530 (Thu, 16 Apr 2020)" );
	script_name( "Microsoft Project 2010 Remote Code Execution Vulnerability (KB4484132)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484132" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Microsoft Project software
  fails to loads arbitrary type libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to take control of the affected system. An attacker could then install programs,
  view, change, or delete data or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Project 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4461631" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_project_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Microsoft/Project/Win/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
proPath = infos["location"];
if(!proPath || ContainsString( proPath, "Did not find install path from registry" )){
	exit( 0 );
}
path = proPath + "\\Office14";
proVer = fetch_file_version( sysPath: path, file_name: "winproj.exe" );
if(!proVer){
	exit( 0 );
}
if(version_in_range( version: proVer, test_version: "14.0.7237.0", test_version2: "14.0.7248.4999" )){
	report = report_fixed_ver( file_checked: path + "\\winproj.exe", file_version: proVer, vulnerable_range: "14.0.7237.0 - 14.0.7248.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

