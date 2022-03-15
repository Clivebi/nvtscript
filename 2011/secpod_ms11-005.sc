if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902290" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)" );
	script_cve_id( "CVE-2011-0040" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Microsoft Windows Active Directory SPN Denial of Service (2478953)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2478953" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0319" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-005" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2003 Service Pack 2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error in Active Directory that does not properly
  process specially crafted requests to update the service principal name (SPN)." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-005." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3 ) <= 0){
	exit( 0 );
}
if(!registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\NTDS" )){
	exit( 0 );
}
if(hotfix_missing( name: "2478953" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ntdsa.dll" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win2003: 3 ) > 0){
	SP = get_kb_item( "SMB/Win2003/ServicePack" );
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "5.2.3790.4808" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4808", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

