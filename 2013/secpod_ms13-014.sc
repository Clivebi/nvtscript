if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902951" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-1281" );
	script_bugtraq_id( 57853 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-02-13 15:29:45 +0530 (Wed, 13 Feb 2013)" );
	script_name( "Microsoft Windows NFS Server Denial of Service Vulnerability (2790978)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2790978" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028129" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-014" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to denial of service." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 R2 Service Pack 2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to a NULL pointer dereference error when handling file
  operations on a read only share and can be exploited to cause the system
  to stop responding and restart." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-014." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Nfssvc.exe" );
if(!exeVer){
	exit( 0 );
}
if(hotfix_check_sp( win2008r2: 2 ) > 0){
	if(version_is_less( version: exeVer, test_version: "6.1.7600.16385" ) || version_in_range( version: exeVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21413" ) || version_in_range( version: exeVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17513" ) || version_in_range( version: exeVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.22206" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

