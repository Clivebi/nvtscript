if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804492" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-4971" );
	script_bugtraq_id( 68764 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-10-15 08:38:41 +0530 (Wed, 15 Oct 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft Windows Message Queuing Service Privilege Escalation Vulnerability (2993254)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS14-062." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error when handling
  objects within the Message Queuing service, which can be exploited to elevate
  privileges by sending a specially crafted IOCTL request." );
	script_tag( name: "impact", value: "Successful exploitation could allow
  local users to gain escalated privileges." );
	script_tag( name: "affected", value: "Microsoft Windows 2003 x32/x64 Service Pack 2 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-062" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2003: 3, win2003x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
win32SysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\drivers\\Mqac.sys" );
if(!win32SysVer){
	exit( 0 );
}
if(hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0){
	if(version_is_less( version: win32SysVer, test_version: "5.2.2008.5417" )){
		report = report_fixed_ver( installed_version: win32SysVer, fixed_version: "5.2.2008.5417", install_path: sysPath );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}

