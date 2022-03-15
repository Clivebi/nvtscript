if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902490" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3868" );
	script_bugtraq_id( 49942 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-17 15:10:19 +0530 (Thu, 17 Nov 2011)" );
	script_name( "VMware Products UDF File Systems Buffer Overflow Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46241" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1026139" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2011-0011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_vmware_prdts_detect_lin.sc" );
	script_mandatory_keys( "VMware/Linux/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execution of arbitrary code." );
	script_tag( name: "affected", value: "Vmware Player version 3.0 before 3.1.5,
  VMware Workstation version 7.0 before 7.1.5" );
	script_tag( name: "insight", value: "The flaw is due to an error when handling UDF filesystem images.This can be
  exploited to cause a buffer overflow via a specially crafted ISO image file." );
	script_tag( name: "summary", value: "The host is installed with VMWare products and are prone to
  buffer overflow vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Vmware Player version 3.1.5 or later  Upgrade to Vmware Workstation version 7.1.5 or later" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2011-0011.html" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Linux/Installed" )){
	exit( 0 );
}
vmplayerVer = get_kb_item( "VMware/Player/Linux/Ver" );
if(vmplayerVer != NULL){
	if(version_in_range( version: vmplayerVer, test_version: "3.0", test_version2: "3.1.4" )){
		report = report_fixed_ver( installed_version: vmplayerVer, vulnerable_range: "3.0 - 3.1.4" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vmworkstnVer = get_kb_item( "VMware/Workstation/Linux/Ver" );
if(vmworkstnVer != NULL){
	if(version_in_range( version: vmworkstnVer, test_version: "7.0", test_version2: "7.1.4" )){
		report = report_fixed_ver( installed_version: vmworkstnVer, vulnerable_range: "7.0 - 7.1.4" );
		security_message( port: 0, data: report );
	}
}

