CPE = "cpe:/a:vmware:vcenter_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105057" );
	script_cve_id( "CVE-2014-0224", "CVE-2014-0198", "CVE-2010-5298", "CVE-2014-3470" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_name( "VMware Security Updates for vCenter Server (VMSA-2014-0006)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2014-0006.html" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-07-04 11:04:01 +0100 (Fri, 04 Jul 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "General" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_vcenter_server_consolidation.sc" );
	script_mandatory_keys( "vmware/vcenter/server/detected", "vmware/vcenter/server/build" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable build is present on the target host." );
	script_tag( name: "insight", value: "a. OpenSSL update for multiple products.

  OpenSSL libraries have been updated in multiple products to versions 0.9.8za and 1.0.1h in order
  to resolve multiple security issues." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "VMware product updates address OpenSSL security vulnerabilities." );
	script_tag( name: "affected", value: "- VMware vCenter Server prior to 5.5u1b

  - VMware vCenter Server prior to 5.1U2a

  - VMware vCenter Server prior to 5.0U3a" );
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
fixed_builds = make_array( "5.5.0", "1891310", "5.1.0", "1917403", "5.0.0", "1923446" );
if(!fixed_builds[version]){
	exit( 0 );
}
if(int( build ) < int( fixed_builds[version] )){
	security_message( port: 0, data: esxi_remote_report( ver: version, build: build, fixed_build: fixed_builds[version], typ: "vCenter" ) );
	exit( 0 );
}
exit( 99 );

