CPE = "cpe:/h:cisco:asr_1000";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105343" );
	script_cve_id( "CVE-2015-6274" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 12106 $" );
	script_name( "Cisco ASR 1000 Series Aggregation Services Routers Data-Plane Processing Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=40708" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv71273" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to cause a denial-of-service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to the processing of excessive number of IPv4 packets that require fragmentation and reassembly. An
attacker could exploit this vulnerability by sending an excessive number of fragmented packets, causing high Cisco QuantumFlow Processor (QFP) CPU utilization in
the Embedded Services Processor (ESP)." );
	script_tag( name: "solution", value: "Please see the vendor advisory for more information and released fixes." );
	script_tag( name: "summary", value: "Cisco ASR 1000 Series Aggregation Services Routers contain a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service condition." );
	script_tag( name: "affected", value: "Cisco ASR 1000 Series 15.5 Base, (3)S" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-09-01 16:17:02 +0200 (Tue, 01 Sep 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_asr_1000_detect.sc" );
	script_mandatory_keys( "cisco_asr_1000/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(vers == "15.5(3)S"){
	report = "Installed version: " + vers + "\n" + "Fixed version:     See vendor advisory";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

