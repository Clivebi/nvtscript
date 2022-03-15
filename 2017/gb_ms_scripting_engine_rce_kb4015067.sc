if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810921" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2017-0158" );
	script_bugtraq_id( 97455 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-12 10:47:16 +0530 (Wed, 12 Apr 2017)" );
	script_name( "Microsoft Windows Scripting Engine Remote Code Execution Vulnerability (KB4015067)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft April 2017 Security Update KB4015067." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the way that the
  VBScript engine handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain the same user rights as the current user. If the current user is logged
  on with administrative user rights, an attacker who successfully exploited this
  vulnerability could take complete control of an affected system. An attacker
  could then install programs, view, change, delete data, or create new
  accounts with full user rights." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-gb/help/4015067" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win2008: 3, winVistax64: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
cdVer = fetch_file_version( sysPath: sysPath, file_name: "Cdosys.dll" );
if(!cdVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0){
	if(version_is_less( version: cdVer, test_version: "6.6.6002.24072" )){
		Vulnerable_range = "Less than 6.6.6002.24072";
		report = "File checked:     " + sysPath + "\\Cdosys.dll" + "\n" + "File version:     " + cdVer + "\n" + "Vulnerable range: Less than 6.6.6002.24072\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

