CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106341" );
	script_cve_id( "CVE-2016-6424" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco ASA Software DHCP Relay Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-asa-dhcp" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the DHCP Relay feature of Cisco ASA Software could allow
an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition by causing an interface
wedge." );
	script_tag( name: "insight", value: "The vulnerability is due to improper handling of resources linked with the
DHCP Relay feature. An attacker could exploit this vulnerability by sending DHCP packets at specific rates." );
	script_tag( name: "impact", value: "An exploit could allow an attacker to cause an interface to become wedged,
and stop processing incoming traffic. Once this state is reached, restoration of service can only be achieved
by reloading the device." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-10-06 12:09:26 +0700 (Thu, 06 Oct 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
check_vers = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
affected = make_list( "8.4.7.29",
	 "9.1.7.4" );
for af in affected {
	if(check_vers == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

