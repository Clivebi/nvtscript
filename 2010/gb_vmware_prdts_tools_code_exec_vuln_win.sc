if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801323" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)" );
	script_cve_id( "CVE-2010-1141", "CVE-2010-1142" );
	script_bugtraq_id( 39394, 39392 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_name( "VMware Products Tools Remote Code Execution Vulnerabilies (win)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39198" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2010-0007.html" );
	script_xref( name: "URL", value: "http://lists.vmware.com/pipermail/security-announce/2010/000090.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "VMware ACE 2.5.x before 2.5.4 build 246459,
  VMware Player 2.5.x before 2.5.4 build 246459,
  VMware Workstation 6.5.x before 6.5.4 build 246459" );
	script_tag( name: "insight", value: "The flaw is due to error in 'tools' which does not properly access libraries.
  This allows attackers to execute arbitrary code by tricking a Windows guest
  OS user into clicking on a file that is stored on a network share." );
	script_tag( name: "summary", value: "The host is installed with VMWare products and are prone to
  remote code execution vulnerabilities." );
	script_tag( name: "solution", value: "Apply updates." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Win/Installed" )){
	exit( 0 );
}
vmplayerVer = get_kb_item( "VMware/Player/Win/Ver" );
if(vmplayerVer != NULL){
	if(version_in_range( version: vmplayerVer, test_version: "2.5", test_version2: "2.5.3" )){
		report = report_fixed_ver( installed_version: vmplayerVer, vulnerable_range: "2.5 - 2.5.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vmworkstnVer = get_kb_item( "VMware/Workstation/Win/Ver" );
if(vmworkstnVer != NULL){
	if(version_in_range( version: vmworkstnVer, test_version: "6.5", test_version2: "6.5.3" )){
		report = report_fixed_ver( installed_version: vmworkstnVer, vulnerable_range: "6.5 - 6.5.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
aceVer = get_kb_item( "VMware/ACE/Win/Ver" );
if(!aceVer){
	aceVer = get_kb_item( "VMware/ACE\\Dormant/Win/Ver" );
	if(aceVer){
		if(version_in_range( version: aceVer, test_version: "2.5", test_version2: "2.5.3" )){
			report = report_fixed_ver( installed_version: aceVer, vulnerable_range: "2.5 - 2.5.3" );
			security_message( port: 0, data: report );
		}
	}
}
vmserVer = get_kb_item( "VMware/Server/Win/Ver" );
if(vmserVer){
	if(version_in_range( version: vmserVer, test_version: "2.0", test_version2: "2.0.1" )){
		report = report_fixed_ver( installed_version: vmserVer, vulnerable_range: "2.0 - 2.0.1" );
		security_message( port: 0, data: report );
	}
}

