CPE = "cpe:/a:cisco:unified_computing_system_platform_emulator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105800" );
	script_cve_id( "CVE-2016-1340", "CVE-2016-1339" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12313 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-07 11:28:50 +0200 (Thu, 07 Jul 2016)" );
	script_name( "Cisco Unified Computing System Platform Emulator Command Injection/Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160414-ucspe1" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160414-ucspe2" );
	script_tag( name: "summary", value: "Cisco Unified Computing System Platform Emulator is prone to multiple vulnerabilities" );
	script_tag( name: "insight", value: "1.
A vulnerability in the Cisco Unified Computing System (UCS) Platform Emulator could allow an authenticated, local attacker to perform a command injection attack.
The vulnerability occurs because the affected system improperly handles ucspe-copy command-line arguments. An attacker could exploit this vulnerability by using crafted command arguments on the system. An exploit could allow the attacker to perform a command injection attack, which could allow the attacker to execute arbitrary commands on the system.

2.
A vulnerability in Cisco Unified Computing System (UCS) Platform Emulator could allow an authenticated, local attacker to trigger a heap-based buffer overflow on a targeted system.

The vulnerability occurs because the affected system improperly handles libclimeta.so filename arguments. An attacker could exploit this vulnerability by sending crafted filename arguments to the system. An exploit could allow the attacker to execute code on the system or cause a denial of service (DoS) condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available" );
	script_tag( name: "affected", value: "Cisco Unified Computing System Platform Emulator < 3.1(1ePE1)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ucs_platform_emulator_web_detect.sc" );
	script_mandatory_keys( "cisco_ucs_plattform_emulator/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^[0-3](\\.|\\()" ) || IsMatchRegexp( version, "3\\.1\\([0-9][a-d]PE" ) || IsMatchRegexp( version, "^3\\.1\\(1ePE0\\)" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1(1ePE1)" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

