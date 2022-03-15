CPE = "cpe:/o:cisco:ios_xr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106251" );
	script_cve_id( "CVE-2016-1433" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco IOS XR Software for NCS 6000 Series Devices OSPF Packet Processing Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-iosxr" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the OSPFv3 processing of Cisco IOS XR Software for
Cisco Network Convergence System (NCS) 6000 Series devices could allow an unauthenticated, remote attacker
to cause a reload of the OSPFv3 process and result in a limited denial of service (DoS) condition on an
affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient logic in the processing of
crafted OSPFv3 packets. An attacker could exploit this vulnerability by sending crafted OSPFv3 packets to be
processed by an affected device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a reload of the OSPFv3 process
and cause a limited DoS condition on the affected device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-09-16 11:53:36 +0700 (Fri, 16 Sep 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_version.sc" );
	script_mandatory_keys( "cisco/ios_xr/version", "cisco/ios_xr/model" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "cisco/ios_xr/model" )){
	exit( 0 );
}
if(!ContainsString( model, "NCS-600" )){
	exit( 99 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "6.0.0",
	 "6.0.1" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

