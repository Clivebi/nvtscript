if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812586" );
	script_version( "2021-06-23T11:43:04+0000" );
	script_cve_id( "CVE-2018-0976" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-23 11:43:04 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-04-11 10:10:51 +0530 (Wed, 11 Apr 2018)" );
	script_name( "Windows Remote Desktop Protocol (RDP) Denial of Service Vulnerability (KB4093227)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft KB4093227." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the Remote Desktop Protocol (RDP) when an
  attacker connects to the target system using RDP and sends specially crafted requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to cause the RDP
  service on the target system to stop responding." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4093227" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
if(!sysPath = smb_get_system32root()){
	exit( 0 );
}
if(!vers = fetch_file_version( sysPath: sysPath, file_name: "scksp.dll" )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "6.0.6002.24329" )){
	report = report_fixed_ver( file_checked: sysPath + "\\scksp.dll", file_version: vers, vulnerable_range: "Less than 6.0.6002.24329" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

