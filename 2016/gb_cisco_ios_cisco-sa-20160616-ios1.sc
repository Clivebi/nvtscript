CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105773" );
	script_cve_id( "CVE-2016-1425" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco IOS Software Link Layer Discovery Protocol Processing Code Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160616-ios1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Link Layer Discovery Protocol (LLDP) packet processing code of Cisco IOS
could allow an unauthenticated, adjacent attacker to cause the crash of an affected device.

The vulnerability is due to improper handling of crafted LLDP packets. An attacker could exploit
this vulnerability by sending a specially crafted LLDP packet. An exploit could allow the attacker
to cause a Denial of Service (DoS) condition on an affected platform.

Cisco has released software updates that address this vulnerability. There are no workarounds that
address this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-06-20 12:50:47 +0200 (Mon, 20 Jun 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_cisco_ios_get_version.sc" );
	script_mandatory_keys( "cisco_ios/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "15.0(2)SG5",
	 "15.1(2)SG3",
	 "15.2(1)E",
	 "15.3(3)S",
	 "15.4(1.13)S" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

