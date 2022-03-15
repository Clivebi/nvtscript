if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811839" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-4924" );
	script_bugtraq_id( 100843 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-10 01:30:00 +0000 (Tue, 10 Oct 2017)" );
	script_tag( name: "creation_date", value: "2017-09-22 12:05:44 +0530 (Fri, 22 Sep 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "VMware ESXi SVGA Device Code Execution Vulnerability (VMSA-2017-0015)" );
	script_tag( name: "summary", value: "The host is installed with VMware ESXi
  and is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if the target host is missing one or more patch(es)." );
	script_tag( name: "insight", value: "The flaw is due to an out-of-bounds write
  error in SVGA device." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  guest to execute code on the host." );
	script_tag( name: "affected", value: "VMware ESXi 6.5 before ESXi650-201707101-SG." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.vmware.com/security/advisories/VMSA-2017-0015.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "VMware Local Security Checks" );
	script_dependencies( "gb_vmware_esxi_init.sc" );
	script_mandatory_keys( "VMware/ESXi/LSC", "VMware/ESX/version" );
	exit( 0 );
}
require("vmware_esx.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "VMware/ESXi/LSC" )){
	exit( 0 );
}
if(!esxVersion = get_kb_item( "VMware/ESX/version" )){
	exit( 0 );
}
patches = make_array( "6.5.0", "VIB:esx-base:6.5.0-0.23.5969300" );
if(!patches[esxVersion]){
	exit( 99 );
}
if(report = esxi_patch_missing( esxi_version: esxVersion, patch: patches[esxVersion] )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

