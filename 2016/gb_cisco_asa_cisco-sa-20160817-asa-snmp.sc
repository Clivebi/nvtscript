CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106183" );
	script_cve_id( "CVE-2016-6366" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_name( "Cisco Adaptive Security Appliance SNMP Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Simple Network Management Protocol (SNMP) code
of Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause
a reload of the affected system or to remotely execute code.

The vulnerability is due to a buffer overflow in the affected code area. An attacker could exploit this
vulnerability by sending crafted SNMP packets to the affected system. An exploit could allow the attacker to
execute arbitrary code and obtain full control of the system or to cause a reload of the affected system. The
attacker must know the SNMP community string to exploit this vulnerability.

Note: Only traffic directed to the affected system can be used to exploit this vulnerability. This vulnerability
affects systems configured in routed and transparent firewall mode only and in single or multiple context mode.
This vulnerability can be triggered by IPv4 traffic only. The attacker requires knowledge of the configured SNMP
community string in SNMP version 1 and SNMP version 2c or a valid username and password for SNMP version 3.

Cisco has released software updates that address this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:31:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2016-08-18 10:57:32 +0700 (Thu, 18 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_is_less( version: check_vers, test_version: "9.0.4.40" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.4(40)" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( check_vers, "^9\\.1" )){
	if(version_is_less( version: check_vers, test_version: "9.1.7.9" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.1.7(9)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( check_vers, "^9\\.2" )){
	if(version_is_less( version: check_vers, test_version: "9.2.4.14" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.2.4(14)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( check_vers, "^9\\.3" )){
	if(version_is_less( version: check_vers, test_version: "9.3.3.10" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.3.3(10)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( check_vers, "^9\\.4" )){
	if(version_is_less( version: check_vers, test_version: "9.4.3.8" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.4.3(8)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( check_vers, "^9\\.5" )){
	if(version_is_less( version: check_vers, test_version: "9.5.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.5(3)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( check_vers, "^9\\.6" )){
	if(version_is_less( version: check_vers, test_version: "9.6.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.6.2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

