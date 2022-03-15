if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806661" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0012" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-01-13 15:09:48 +0530 (Wed, 13 Jan 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Visual Basic ASLR Bypass Vulnerability (3124585)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-004." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error within Microsoft
  Office which fails to use the Address Space Layout Randomization (ASLR) security
  feature, allowing an attacker to more reliably predict the memory offsets of
  specific instructions in a given call stack." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass Address Space Layout Randomization (ASLR) security feature." );
	script_tag( name: "affected", value: "Microsoft Visual Basic 6.0 Runtime." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3096896" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-004" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( item: "DisplayName", key: key + item );
		if(ContainsString( appName, "Microsoft Visual Basic" )){
			sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Mscomctl.Ocx" );
			if(sysVer){
				if(version_is_less( version: sysVer, test_version: "6.1.98.46" )){
					report = "File checked:     " + sysPath + "\\system32\\Mscomctl.Ocx" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + "Less than 6.1.98.46" + "\n";
					security_message( data: report );
					exit( 0 );
				}
			}
		}
	}
}

