CPE = "cpe:/a:vmware:vcenter_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105764" );
	script_cve_id( "CVE-2015-6931" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_name( "VMware Security Updates for vCenter Server (VMSA-2016-0009)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0009.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable build is present on the target host." );
	script_tag( name: "insight", value: "The vSphere Web Client contains a reflected cross-site scripting
  vulnerability due to a lack of input sanitization. An attacker can exploit this issue by tricking
  a victim into clicking a malicious link." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "VMware vCenter Server updates address an important refelctive
  cross-site scripting issue." );
	script_tag( name: "affected", value: "- VMware vCenter Server 5.5 prior to 5.5 update 2d

  - VMware vCenter Server 5.1 prior to 5.1 update 3d

  - VMware vCenter Server 5.0 prior to 5.0 update 3g" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-15 12:04:27 +0200 (Wed, 15 Jun 2016)" );
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
if(version == "5.0.0"){
	if(int( build ) < int( 3891026 )){
		fix = "5.0 U3g";
	}
}
if(version == "5.1.0"){
	if(int( build ) < int( 3814779 )){
		fix = "5.1 U3d";
	}
}
if(version == "5.5.0"){
	if(int( build ) < int( 2442328 )){
		fix = "5.5 U2d";
	}
}
if(fix){
	security_message( port: 0, data: esxi_remote_report( ver: version, build: build, fixed_build: fix, typ: "vCenter" ) );
	exit( 0 );
}
exit( 99 );

