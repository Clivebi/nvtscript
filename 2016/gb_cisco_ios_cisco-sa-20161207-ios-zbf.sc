CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106449" );
	script_cve_id( "CVE-2016-9201" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 12149 $" );
	script_name( "Cisco IOS Software Zone-Based Firewall Feature Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-ios-zbf" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Zone-Based Firewall feature of Cisco IOS Software
could allow an unauthenticated, remote attacker to pass traffic that should otherwise have been dropped based on
the configuration." );
	script_tag( name: "insight", value: "The vulnerability is due to a logic flaw in a corner case scenario." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by sending traffic that would
have been dropped by the policy." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-08 14:16:20 +0700 (Thu, 08 Dec 2016)" );
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
if(version == "15.3(3)M3"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

