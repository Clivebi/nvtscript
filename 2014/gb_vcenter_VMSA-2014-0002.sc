CPE = "cpe:/a:vmware:vcenter_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103917" );
	script_cve_id( "CVE-2013-5211", "CVE-2013-4332" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_name( "VMware Security Updates for vCenter Server (VMSA-2014-0002)" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-03-12 14:24:01 +0100 (Wed, 12 Mar 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_vcenter_server_consolidation.sc" );
	script_mandatory_keys( "vmware/vcenter/server/detected", "vmware/vcenter/server/build" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2014-0002.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable build is present on the target host." );
	script_tag( name: "insight", value: "a. DDoS vulnerability in NTP third party libraries

  The NTP daemon has a DDoS vulnerability in the handling of the 'monlist' command. An attacker may
  send a forged request to a vulnerable NTP server resulting in an amplified response to the
  intended target of the DDoS attack.

  b. Update to ESXi glibc package

  The ESXi glibc package is updated to version glibc-2.5-118.el5_10.2 to resolve a security issue.

  c. vCenter and Update Manager, Oracle JRE 1.7 Update 45

  Oracle JRE is updated to version JRE 1.7 Update 45, which addresses multiple security issues that
  existed in earlier releases of Oracle JRE." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware vSphere updates to third party libraries." );
	script_tag( name: "affected", value: "VMware vCenter Server 5.5 prior 5.5 Update 1." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("vmware_esx.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!build = get_kb_item( "vmware/vcenter/server/build" )){
	exit( 0 );
}
fixed_builds = make_array( "5.5.0", "1623099" );
if(!fixed_builds[version]){
	exit( 0 );
}
if(int( build ) < int( fixed_builds[version] )){
	security_message( port: 0, data: esxi_remote_report( ver: version, build: build, fixed_build: fixed_builds[version], typ: "vCenter" ) );
	exit( 0 );
}
exit( 99 );

