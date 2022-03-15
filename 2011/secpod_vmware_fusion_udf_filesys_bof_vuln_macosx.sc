if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902634" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3868" );
	script_bugtraq_id( 49942 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-17 17:54:28 +0530 (Thu, 17 Nov 2011)" );
	script_name( "VMware Fusion UDF File Systems Buffer Overflow Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46241" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1026139" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2011-0011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_vmware_fusion_detect_macosx.sc" );
	script_mandatory_keys( "VMware/Fusion/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execution of arbitrary code." );
	script_tag( name: "affected", value: "Vmware Fusion 3.1.0 before 3.1.3" );
	script_tag( name: "insight", value: "The flaw is due to an error when handling UDF filesystem images. This can be
  exploited to cause a buffer overflow via a specially crafted ISO image file." );
	script_tag( name: "summary", value: "The host is installed with VMWare Fusion and are prone to
  buffer overflow vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Vmware Fusion version 3.1.3 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Fusion/MacOSX/Version" )){
	exit( 0 );
}
vmfusionVer = get_kb_item( "VMware/Fusion/MacOSX/Version" );
if(vmfusionVer != NULL){
	if(version_in_range( version: vmfusionVer, test_version: "3.1.0", test_version2: "3.1.2" )){
		report = report_fixed_ver( installed_version: vmfusionVer, vulnerable_range: "3.1.0 - 3.1.2" );
		security_message( port: 0, data: report );
	}
}

