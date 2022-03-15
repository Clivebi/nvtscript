if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814204" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8421" );
	script_bugtraq_id( 105222 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-05 15:46:00 +0000 (Mon, 05 Nov 2018)" );
	script_tag( name: "creation_date", value: "2018-09-12 10:55:22 +0530 (Wed, 12 Sep 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft .NET Framework RCE Vulnerability (KB4457044)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4457044" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error within the
  application when Microsoft .NET Framework processes untrusted input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to take control of an affected system. An attacker could then install
  programs, view, change, delete data or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 3.5.1 for Microsoft Windows 7 SP1 and Microsoft Windows Server 2008 R2 SP1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4457044" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	dotPath = registry_get_sz( key: key + item, item: "Path" );
	if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
		sysdllVer = fetch_file_version( sysPath: dotPath, file_name: "system.workflow.runtime.dll" );
		if(!sysdllVer || !IsMatchRegexp( sysdllVer, "^3\\." )){
			continue;
		}
		if(version_in_range( version: sysdllVer, test_version: "3.0.4203.0", test_version2: "3.0.4203.8810" )){
			report = report_fixed_ver( file_checked: dotPath + "system.workflow.runtime.dll", file_version: sysdllVer, vulnerable_range: "3.0.4203.0 - 3.0.4203.8810" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

