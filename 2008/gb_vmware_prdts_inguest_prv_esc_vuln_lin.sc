if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800072" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4915", "CVE-2008-4917" );
	script_bugtraq_id( 32168 );
	script_name( "VMware Products Trap Flag In-Guest Privilege Escalation Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/3052" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2008-0018.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_lin.sc" );
	script_mandatory_keys( "VMware/Linux/Installed" );
	script_tag( name: "affected", value: "VMware Server 1.x - 1.0.7 on Linux

  VMware Player 1.x - 1.0.8 and 2.x - 2.0.5 on Linux

  VMware Workstation 6.0.5 and earlier on all Linux" );
	script_tag( name: "insight", value: "The issue is due to an error in the CPU hardware emulation while
  handling the trap flag." );
	script_tag( name: "summary", value: "The host is installed with VMWare product(s) that are vulnerable
  to privilege escalation vulnerability." );
	script_tag( name: "solution", value: "Upgrade VMware to the latest version." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary code
  on the affected system and users could bypass certain security restrictions
  or can gain escalated privileges." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vmserverVer = get_kb_item( "VMware/Server/Linux/Ver" );
if(vmserverVer){
	if(version_is_less_equal( version: vmserverVer, test_version: "1.0.7" )){
		report = report_fixed_ver( installed_version: vmserverVer, vulnerable_range: "Less than or equal to 1.0.7" );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}
vmplayerVer = get_kb_item( "VMware/Player/Linux/Ver" );
if(vmplayerVer){
	if( version_is_less_equal( version: vmplayerVer, test_version: "1.0.8" ) ){
		report = report_fixed_ver( installed_version: vmplayerVer, vulnerable_range: "Less than or equal to 1.0.8" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if(version_in_range( version: vmplayerVer, test_version: "2.0", test_version2: "2.0.5" )){
			report = report_fixed_ver( installed_version: vmplayerVer, vulnerable_range: "2.0 - 2.0.5" );
			security_message( port: 0, data: report );
		}
	}
	exit( 0 );
}
vmworkstnVer = get_kb_item( "VMware/Workstation/Linux/Ver" );
if(vmworkstnVer){
	if( version_in_range( version: vmworkstnVer, test_version: "5.0", test_version2: "5.5.8" ) ){
		report = report_fixed_ver( installed_version: vmworkstnVer, vulnerable_range: "5.0 - 5.5.8" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if(version_in_range( version: vmworkstnVer, test_version: "6.0", test_version2: "6.0.5" )){
			report = report_fixed_ver( installed_version: vmworkstnVer, vulnerable_range: "6.0 - 6.0.5" );
			security_message( port: 0, data: report );
		}
	}
	exit( 0 );
}

