if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817658" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-1647" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-14 19:28:00 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-13 08:24:09 +0530 (Wed, 13 Jan 2021)" );
	script_name( "Microsoft Security Essentials Remote Code Execution Vulnerability - Jan 2021" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Security Updates released for Microsoft Security
  Essentials Protection Engine dated 12-01-2021" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host" );
	script_tag( name: "insight", value: "The flaw exists while opening a malicious
  document on a system where Microsoft Security Essentials is installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "Microsoft Security Essentials." );
	script_tag( name: "solution", value: "Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1647" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Microsoft Antimalware";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
def_version = registry_get_sz( key: "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Signature Updates", item: "EngineVersion" );
if(!def_version){
	exit( 0 );
}
if(version_is_less( version: def_version, test_version: "1.1.17700.4" )){
	report = report_fixed_ver( installed_version: def_version, fixed_version: "1.1.17700.4 or higher" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

