if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900465" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-05 06:25:55 +0100 (Thu, 05 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2008-6194" );
	script_name( "Microsoft Windows DNS Memory Corruption Vulnerability - Mar09" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-062" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/491831/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/491815/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "affected", value: "Microsoft Windows Server 2000 and 2003." );
	script_tag( name: "insight", value: "This flaw is due to memory leak vulnerability in Microsoft Windows DNS
  Server through DNS packets." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is running Microsoft Windows and is prone to DNS Memory
  Corruption Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in
  the context of the application and can cause memory corruption in the DNS
  service." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(hotfix_check_sp( win2k: 5, win2003: 3 ) <= 0){
	exit( 0 );
}
sys32Path = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(!sys32Path){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sys32Path );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sys32Path + "\\dns.exe" );
dnsVer = GetVer( file: file, share: share );
if(dnsVer != NULL){
	if(get_kb_item( "SMB/Win2K/ServicePack" )){
		if(version_is_less_equal( version: dnsVer, test_version: "5.0.2195.7147" )){
			report = report_fixed_ver( installed_version: dnsVer, vulnerable_range: "Less than or equal to 5.0.2195.7147" );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	SP = get_kb_item( "SMB/Win2003/ServicePack" );
	if( ContainsString( SP, "Service Pack 1" ) ){
		if(version_is_less_equal( version: dnsVer, test_version: "5.2.3790.3027" )){
			report = report_fixed_ver( installed_version: dnsVer, vulnerable_range: "Less than or equal to 5.2.3790.3027" );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	else {
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less_equal( version: dnsVer, test_version: "5.2.3790.4171" )){
				report = report_fixed_ver( installed_version: dnsVer, vulnerable_range: "Less than or equal to 5.2.3790.4171" );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

