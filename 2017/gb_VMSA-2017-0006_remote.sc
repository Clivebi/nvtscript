if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140231" );
	script_cve_id( "CVE-2017-4902", "CVE-2017-4903", "CVE-2017-4904", "CVE-2017-4905" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_name( "VMSA-2017-0006: VMware ESXi updates address critical and moderate security issues (remote check)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2017-0006.html" );
	script_tag( name: "vuldetect", value: "Check the build number" );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware ESXi, Workstation and Fusion updates address critical and moderate
security issues.

ESXi has a heap buffer overflow and uninitialized stack memory usage in SVGA. These issues may allow a guest to execute code on the host." );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-31 10:54:50 +0200 (Fri, 31 Mar 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_esx_web_detect.sc" );
	script_mandatory_keys( "VMware/ESX/build", "VMware/ESX/version" );
	exit( 0 );
}
require("vmware_esx.inc.sc");
if(!esxVersion = get_kb_item( "VMware/ESX/version" )){
	exit( 0 );
}
if(!esxBuild = get_kb_item( "VMware/ESX/build" )){
	exit( 0 );
}
fixed_builds = make_array( "6.0.0", "5224934", "6.5.0", "5224529" );
if(!fixed_builds[esxVersion]){
	exit( 0 );
}
if(int( esxBuild ) < int( fixed_builds[esxVersion] )){
	security_message( port: 0, data: esxi_remote_report( ver: esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
	exit( 0 );
}
exit( 99 );

