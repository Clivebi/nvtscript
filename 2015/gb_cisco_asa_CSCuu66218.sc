CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106011" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-06-23 09:56:22 +0700 (Tue, 23 Jun 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-4550" );
	script_name( "Cisco ASA AES-GCM Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	script_tag( name: "summary", value: "Cisco ASA is prone to an encrypted IPSec or IKEv2 modification
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to an error on the firmware of the
Cavium Networks cryptographic module. Due to this vulnerability, the integrity check value (ICV) is not
verified. An attacker could exploit this vulnerability by intercepting encrypted packets in transit and
modifying their contents. Such packets would be decrypted by the ASA and then forwarded to their destination,
without the modification being detected." );
	script_tag( name: "impact", value: "An unauthenticated, remote attacker could modify the contents of an
encrypted IPSec or IKEv2 packet. A successful exploit could be leveraged to conduct further attacks." );
	script_tag( name: "affected", value: "Version 9.3 and 9.4" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=39366" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(( revcomp( a: compver, b: "9.3.3.2" ) <= 0 ) && ( revcomp( a: compver, b: "9.3" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.3(3.2)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "9.4.1.2" ) <= 0 ) && ( revcomp( a: compver, b: "9.4" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.4(1.2)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

