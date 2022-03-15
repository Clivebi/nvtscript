CPE = "cpe:/o:cisco:ios_xe";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106175" );
	script_cve_id( "CVE-2016-1478" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-01-26T03:06:23+0000" );
	script_name( "Cisco IOS XE Software Crafted Network Time Protocol Packets Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160804-wedge" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the processing of Network Time Protocol (NTP)
packets by Cisco IOS XE could allow an unauthenticated, remote attacker to cause an interface wedge and an
eventual denial of service (DoS) condition on the affected device.

The vulnerability is due to insufficient checks on clearing the invalid NTP packets from the
interface queue. An attacker could exploit this vulnerability by sending a number of crafted NTP
packets to be processed by an affected device. An exploit could allow the attacker to cause an
interface wedge and an eventual denial of service (DoS) condition on the affected device.

Cisco has released software updates that address this vulnerability. There are no workarounds that
address this vulnerability. However, there is a mitigation for this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-01-26 03:06:23 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-08-10 15:45:16 +0700 (Wed, 10 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xe_consolidation.sc" );
	script_mandatory_keys( "cisco/ios_xe/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "3.16.3S",
	 "3.17.2S",
	 "3.18.1S" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

