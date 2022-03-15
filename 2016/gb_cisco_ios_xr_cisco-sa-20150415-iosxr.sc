CPE = "cpe:/o:cisco:ios_xr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105688" );
	script_cve_id( "CVE-2015-0695" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco IOS XR Software BVI Routed Packet Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150415-iosxr" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the packet-processing code of Cisco IOS XR Software for
  Cisco ASR 9000 Series Aggregation Services Routers (ASR) could allow an unauthenticated, remote attacker to
  cause a lockup and eventual reload of a network processor chip and the line card that is processing traffic.
  Only Typhoon-based line cards on Cisco ASR 9000 Series Aggregation Services Routers are affected by this vulnerability.

  The vulnerability is due to improper processing of packets that are routed via the bridge-group virtual interface (BVI)
  when any of the following features are configured: Unicast Reverse Path Forwarding (uRPF), policy-based routing (PBR),
  quality of service (QoS), or access control lists (ACLs). An attacker could exploit this vulnerability by sending IPv4
  packets through an affected device that is configured to route them via the BVI interface. A successful exploit could allow
  the attacker to cause a lockup and eventual reload of a network processor chip and the line card that is processing traffic,
  leading to a denial of service (DoS) condition.

  Cisco has released software updates that address this vulnerability. There are no workarounds to address this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-05-10 14:03:30 +0200 (Tue, 10 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_version.sc" );
	script_mandatory_keys( "cisco/ios_xr/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!model = get_kb_item( "cisco/ios_xr/model" )){
	exit( 0 );
}
if(!ContainsString( model, "ASR9" )){
	exit( 99 );
}
affected = make_list( "4.3.0",
	 "4.3.1",
	 "4.3.2",
	 "4.3.3",
	 "5.1.0",
	 "5.1.1",
	 "5.1.2",
	 "5.2.0",
	 "5.2.1" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

