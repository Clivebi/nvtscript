CPE = "cpe:/a:vmware:vcenter_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105848" );
	script_cve_id( "CVE-2016-5331" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_name( "VMware Security Updates for vCenter Server (VMSA-2016-0010)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0010.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable build is present on the target host." );
	script_tag( name: "solution", value: "Update to version 6.0 U2 or later." );
	script_tag( name: "summary", value: "vCenter Server contain an HTTP header injection vulnerability
  due to lack of input validation." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to set arbitrary HTTP response
  headers and cookies, which may allow for cross-site scripting and malicious redirect attacks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-05 15:46:04 +0200 (Fri, 05 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_vcenter_server_consolidation.sc" );
	script_mandatory_keys( "vmware/vcenter/server/detected", "vmware/vcenter/server/build" );
	exit( 0 );
}
require("vmware_esx.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!build = get_kb_item( "vmware/vcenter/server/build" )){
	exit( 0 );
}
if(version == "6.0.0"){
	if(int( build ) < int( 3634788 )){
		fix = "6.0 U2 (Build 3634788)";
	}
}
if(fix){
	security_message( port: 0, data: esxi_remote_report( ver: version, build: build, fixed_build: fix, typ: "vCenter" ) );
	exit( 0 );
}
exit( 99 );

