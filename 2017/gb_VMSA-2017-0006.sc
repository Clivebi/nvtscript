if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140230" );
	script_cve_id( "CVE-2017-4902", "CVE-2017-4903", "CVE-2017-4904", "CVE-2017-4905" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_name( "VMware ESXi updates address critical and moderate security issues (VMSA-2017-0006)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2017-0006.html" );
	script_tag( name: "vuldetect", value: "Checks if the target host is missing one or more patch(es)." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware ESXi updates address critical and moderate
  security issues." );
	script_tag( name: "insight", value: "ESXi has a heap buffer overflow and uninitialized stack memory usage in SVGA.
  These issues may allow a guest to execute code on the host." );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-31 10:40:50 +0200 (Fri, 31 Mar 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "VMware Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
patches = make_array( "6.0.0", "VIB:esx-base:6.0.0-3.58.5224934", "6.5.0", "VIB:esx-base:6.5.0-0.15.5224529" );
if(!patches[esxVersion]){
	exit( 99 );
}
if(report = esxi_patch_missing( esxi_version: esxVersion, patch: patches[esxVersion] )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

