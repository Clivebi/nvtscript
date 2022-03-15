if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811492" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2017-8558" );
	script_bugtraq_id( 99262 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-14 14:07:22 +0530 (Fri, 14 Jul 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Security Essentials Remote Code Execution Vulnerability Jul17" );
	script_tag( name: "summary", value: "This host is installed with Security
  Essentials and is prone to remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the Microsoft Malware
  Protection Engine does not properly scan a specially crafted file leading to
  memory corruption." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the security context of the LocalSystem account and
  take control of the system. An attacker could then install programs. View, change,
  or delete data or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Security Essentials." );
	script_tag( name: "solution", value: "Microsoft Malware Protection Engine's built-in
  mechanism for the automatic detection and deployment of updates will apply the
  update within 48 hours of release." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/2510781" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8558" );
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
key = "SOFTWARE\\Microsoft\\Microsoft Antimalware";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
def_version = registry_get_sz( key: "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Signature Updates", item: "EngineVersion" );
if(!def_version){
	exit( 0 );
}
if(version_is_less( version: def_version, test_version: "1.1.13903.0" )){
	report = "Installed version : " + def_version + "\n" + "Vulnerable range: Less than 1.1.13903.0";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );
