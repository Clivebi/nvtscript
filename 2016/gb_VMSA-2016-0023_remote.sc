if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140101" );
	script_cve_id( "CVE-2016-7463" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_name( "VMSA-2016-003: VMware ESXi updates address a cross-site scripting issue (remote check)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0023.html" );
	script_tag( name: "vuldetect", value: "Check the build number" );
	script_tag( name: "insight", value: "The ESXi Host Client contains a vulnerability that may allow for stored cross-site scripting (XSS). The issue can be introduced by an attacker that has permission to manage virtual machines through ESXi Host Client or by tricking the vSphere administrator to import a specially crafted VM. The issue may be triggered on the system from where ESXi Host Client is used to manage the specially crafted VM." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware product updates address a critical glibc security vulnerability" );
	script_tag( name: "affected", value: "ESXi 6.0 without patch ESXi600-201611102-SG
ESXi 5.5 without patch ESXi550-201612102-SG" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-31 02:59:00 +0000 (Sat, 31 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-12-21 16:22:14 +0100 (Wed, 21 Dec 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
fixed_builds = make_array( "6.0.0", "4558694", "5.5.0", "4756874" );
if(!fixed_builds[esxVersion]){
	exit( 0 );
}
if(int( esxBuild ) < int( fixed_builds[esxVersion] )){
	security_message( port: 0, data: esxi_remote_report( ver: esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
	exit( 0 );
}
exit( 99 );

