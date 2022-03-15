CPE = "cpe:/a:vmware:vcenter_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811838" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_cve_id( "CVE-2017-4926" );
	script_bugtraq_id( 100844 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-21 15:20:00 +0000 (Thu, 21 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-22 12:05:44 +0530 (Fri, 22 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "VMware vCenter Server H5 Client Stored XSS Vulnerability (VMSA-2017-0015)" );
	script_tag( name: "summary", value: "VMware vCenter Server is prone to a cross-site scripting (XSS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable build is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper input handling in vCenter Server
  H5 Client." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker with VC user
  privileges to inject malicious java-scripts which will get executed when other VC users access the
  page." );
	script_tag( name: "affected", value: "VMware vCenter Server 6.5 prior to 6.5 U1." );
	script_tag( name: "solution", value: "Update to version 6.5 U1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.vmware.com/security/advisories/VMSA-2017-0015.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_vmware_vcenter_server_consolidation.sc" );
	script_mandatory_keys( "vmware/vcenter/server/detected", "vmware/vcenter/server/build" );
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
if(IsMatchRegexp( version, "^6\\.5" ) && int( build ) < int( 5973321 )){
	security_message( port: 0, data: esxi_remote_report( ver: version, build: build, fixed_build: "6.5 U1", typ: "vCenter" ) );
	exit( 0 );
}
exit( 99 );

