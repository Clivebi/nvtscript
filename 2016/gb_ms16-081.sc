if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807838" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_cve_id( "CVE-2016-3226" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-06-15 09:02:15 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows Active Directory Denial of Service Vulnerability (3160352)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-081." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some error in Active
  Directory when an authenticated attacker creates multiple machine accounts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service vulnerability." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2012/2012R2

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3160352" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-081" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008r2: 2, win2012: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ntdsai.dll" );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( win2012R2: 1 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "6.3.9600.18331" )){
		Vulnerable_range = "Less than 6.3.9600.18331";
		VULN = TRUE;
	}
}
else {
	if( hotfix_check_sp( win2012: 1 ) > 0 ){
		if(version_is_less( version: dllVer, test_version: "6.2.9200.21856" )){
			Vulnerable_range = "Less than 6.2.9200.21856";
			VULN = TRUE;
		}
	}
	else {
		if(hotfix_check_sp( win2008r2: 2 ) > 0){
			if(version_is_less( version: dllVer, test_version: "6.1.7601.23445" )){
				Vulnerable_range = "Less than 6.1.7601.23445";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\system32\\Ntdsai.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

