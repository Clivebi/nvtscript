CPE = "cpe:/o:cisco:ios_xr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105646" );
	script_cve_id( "CVE-2016-1376" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 11938 $" );
	script_name( "Cisco IOS XR for Cisco ASR 9000 Series Aggregation Services Routers Interface Flap Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160412-asr" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by sending crafted packets to be processed by a line card of an affected device. A successful exploit could allow the attacker to cause CRC and symbol errors on the receiving interface of the device, which may lead to an interface flap." );
	script_tag( name: "vuldetect", value: "Check the IOS XR Version" );
	script_tag( name: "insight", value: "The vulnerability is due to improper processing of packets that contain certain crafted bit patterns." );
	script_tag( name: "solution", value: "See advisory for a solution" );
	script_tag( name: "summary", value: "A vulnerability in packet processing functions of Cisco IOS XR Software running on Cisco ASR 9000 Series Aggregation Services Routers could allow an unauthenticated, remote attacker to cause cyclic redundancy check (CRC) and symbol errors on the receiving interface of an affected device, which may lead to an interface flap." );
	script_tag( name: "last_modification", value: "$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-05-04 17:40:34 +0200 (Wed, 04 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_version.sc" );
	script_mandatory_keys( "cisco/ios_xr/version", "cisco/ios_xr/model" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "cisco/ios_xr/model" )){
	exit( 0 );
}
if(!ContainsString( model, "ASR9K" )){
	exit( 99 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "4.2.3",
	 "4.3.0",
	 "4.3.2",
	 "4.3.4",
	 "5.3.1" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See vendor advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

