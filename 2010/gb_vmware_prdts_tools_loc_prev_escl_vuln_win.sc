if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801561" );
	script_version( "$Revision: 11553 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)" );
	script_cve_id( "CVE-2010-4297" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "VMware Products Tools Local Privilege Escalation Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/514995" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2010-0018.html" );
	script_xref( name: "URL", value: "http://lists.vmware.com/pipermail/security-announce/2010/000112.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
code with elevated privileges, this may aid in other attacks." );
	script_tag( name: "affected", value: "VMware Server version  2.x
VMware Player 2.5.x before 2.5.5 build 328052 and 3.1.x before 3.1.2 build 301548
VMware Workstation 6.5.x before 6.5.5 build 328052 and 7.x before 7.1.2 build 301548" );
	script_tag( name: "insight", value: "The flaw is due to an error in Tools update functionality, which
allows host OS users to gain privileges on the guest OS via unspecified
vectors." );
	script_tag( name: "summary", value: "The host is installed with VMWare products tools local privilege
escalation vulnerability." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Win/Installed" )){
	exit( 0 );
}
vmplayerVer = get_kb_item( "VMware/Player/Win/Ver" );
if(vmplayerVer != NULL){
	if(version_in_range( version: vmplayerVer, test_version: "2.5", test_version2: "2.5.4" ) || version_in_range( version: vmplayerVer, test_version: "3.0", test_version2: "3.1.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vmworkstnVer = get_kb_item( "VMware/Workstation/Win/Ver" );
if(vmworkstnVer != NULL){
	if(version_in_range( version: vmworkstnVer, test_version: "6.5", test_version2: "6.5.4" ) || version_in_range( version: vmworkstnVer, test_version: "7.0", test_version2: "7.1.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vmserVer = get_kb_item( "VMware/Server/Win/Ver" );
if(vmserVer){
	if(IsMatchRegexp( vmserVer, "^2.*" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

