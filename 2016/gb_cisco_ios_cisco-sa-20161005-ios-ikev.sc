CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106336" );
	script_cve_id( "CVE-2016-6423" );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:C" );
	script_version( "$Revision: 12096 $" );
	script_name( "Cisco IOS IKEv2 Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-ios-ikev" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Internet Key Exchange version 2 (IKEv2) code of
Cisco IOS could allow an unauthenticated, remote attacker to cause a reload of the affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to improper handling of crafted IKEv2 packets. The
vulnerability applies only to IKEv2 devices acting as clients or IKEv2 initiators. An attacker could exploit this
vulnerability by sending crafted packets to the affected devices. An attacker, however, would need to be able to
force the affected device to connect to a rogue IKEv2 server under its control." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a reload of the affected
system." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-10-06 11:24:50 +0700 (Thu, 06 Oct 2016)" );
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
if(version == "15.5(3)M"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

