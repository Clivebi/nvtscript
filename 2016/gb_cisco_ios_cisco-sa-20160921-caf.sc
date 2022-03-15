CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106277" );
	script_cve_id( "CVE-2016-6410" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:N/A:N" );
	script_version( "$Revision: 12313 $" );
	script_name( "Cisco IOS Software Application-Hosting Framework Unauthorized File Access Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160921-caf" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Cisco application-hosting framework (CAF) for
Cisco IOS Software with the IOx feature set could allow an authenticated, remote attacker to read arbitrary
files on a targeted system." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation by the affected
framework. An attacker could exploit this vulnerability by submitting specific, crafted input to the affected
framework." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to read arbitrary files on
the targeted system." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-22 10:06:54 +0700 (Thu, 22 Sep 2016)" );
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
if(version == "15.5(2)T"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

