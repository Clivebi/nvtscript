if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103850" );
	script_cve_id( "CVE-2013-3519" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14186 $" );
	script_name( "VMSA-2013-0014 VMware Workstation, Fusion, ESXi and ESX patches address a guest privilege escalation (remote check)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2013-0014.html" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 14:57:54 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-04 10:04:01 +0100 (Wed, 04 Dec 2013)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_esx_web_detect.sc" );
	script_mandatory_keys( "VMware/ESX/build", "VMware/ESX/version" );
	script_tag( name: "vuldetect", value: "Check the build number." );
	script_tag( name: "insight", value: "a. VMware LGTOSYNC privilege escalation.

VMware ESX, Workstation and Fusion contain a vulnerability in the
handling of control code in lgtosync.sys. A local malicious user may
exploit this vulnerability to manipulate the memory allocation. This
could result in a privilege escalation on 32-bit Guest Operating
Systems running Windows 2000 Server, Windows XP or Windows 2003 Server
on ESXi and ESX, or Windows XP on Workstation and Fusion.

The vulnerability does not allow for privilege escalation from the
Guest Operating System to the host. This means that host memory can
not be manipulated from the Guest Operating System." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware Workstation, Fusion, ESXi and ESX patches
  address a vulnerability in the LGTOSYNC.SYS driver which could result
  in a privilege escalation on older Windows-based Guest Operating Systems." );
	script_tag( name: "affected", value: "VMware Workstation 9.x prior to version 9.0.3

  VMware Player 5.x prior to version 5.0.3

  VMware Fusion 5.x prior to version 5.0.4

  VMware ESXi 5.1 without patch ESXi510-201304102

  VMware ESXi 5.0 without patch ESXi500-201303102

  VMware ESXi 4.1 without patch ESXi410-201301402

  VMware ESXi 4.0 without patch ESXi400-201305401

  VMware ESX 4.1 without patch ESX410-201301401

  VMware ESX 4.0 without patch ESX400-201305401" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("vmware_esx.inc.sc");
if(!esxVersion = get_kb_item( "VMware/ESX/version" )){
	exit( 0 );
}
if(!esxBuild = get_kb_item( "VMware/ESX/build" )){
	exit( 0 );
}
fixed_builds = make_array( "5.0.0", "1022489", "5.1.0", "1063671" );
if(!fixed_builds[esxVersion]){
	exit( 0 );
}
if(int( esxBuild ) < int( fixed_builds[esxVersion] )){
	security_message( port: 0, data: esxi_remote_report( ver: esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
	exit( 0 );
}
exit( 99 );

