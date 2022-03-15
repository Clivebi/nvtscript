if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801949" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_cve_id( "CVE-2011-1787", "CVE-2011-2146" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "VMware Products Multiple Vulnerabilities (Linux) -june11" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_lin.sc" );
	script_mandatory_keys( "VMware/Linux/Installed" );
	script_xref( name: "URL", value: "http://kb.vmware.com/kb/1035110" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2011-0009.html" );
	script_xref( name: "URL", value: "http://lists.vmware.com/pipermail/security-announce/2011/000141.html" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to gain privileges on the guest OS." );
	script_tag( name: "affected", value: "VMware ESX 3.0.3 to 4.1

  VMware Player 3.1.x before 3.1.4

  VMware Workstation 7.1.x before 7.1.4" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An information disclosure vulnerability in 'Mount.vmhgfs', allows guest OS
    users to determine the existence of host OS files and directories via
    unspecified vectors.

  - A race condition privilege escalation in 'Mount.vmhgfs' via a race condition,
    that allows guest OS users to gain privileges on the guest OS by mounting a
    file system on top of an arbitrary directory." );
	script_tag( name: "summary", value: "The host is installed with VMWare product(s) which are vulnerable
  to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch or update to player 3.1.4 or later

  Apply the patch or update to VMware Workstation 7.1.4 or later

  Apply the patch for VMware ESX" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Linux/Installed" )){
	exit( 0 );
}
vmpVer = get_kb_item( "VMware/Player/Linux/Ver" );
if(vmpVer){
	if(version_in_range( version: vmpVer, test_version: "3.1.0", test_version2: "3.1.3" )){
		report = report_fixed_ver( installed_version: vmpVer, vulnerable_range: "3.1.0 - 3.1.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vmwtnVer = get_kb_item( "VMware/Workstation/Linux/Ver" );
if(vmwtnVer){
	if(version_in_range( version: vmwtnVer, test_version: "7.1.0", test_version2: "7.1.3" )){
		report = report_fixed_ver( installed_version: vmwtnVer, vulnerable_range: "7.1.0 - 7.1.3" );
		security_message( port: 0, data: report );
	}
}
vmesx = get_kb_item( "VMware/Esx/Linux/Ver" );
if(vmesx){
	if(version_in_range( version: vmesx, test_version: "3.0.3", test_version2: "4.1.0" )){
		report = report_fixed_ver( installed_version: vmesx, vulnerable_range: "3.0.3 - 4.1.0" );
		security_message( port: 0, data: report );
	}
}

