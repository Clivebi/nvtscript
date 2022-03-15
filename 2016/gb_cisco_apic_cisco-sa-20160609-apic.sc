CPE = "cpe:/a:cisco:application_policy_infrastructure_controller";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105750" );
	script_cve_id( "CVE-2016-1420" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco Application Policy Infrastructure Controller Binary Files Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160609-apic" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the installation procedure for Cisco Application Policy Infrastructure Controller
(APIC) devices could allow an authenticated, local attacker to gain root-level privileges.

The vulnerability is due to the use of incorrect installation and permissions settings for binary
files during installation of the system software on a device. An attacker could exploit this
vulnerability by logging in to the device and escalating their privileges. A successful exploit
could allow the attacker to gain root-level privileges and take full control of the device.

Cisco has released software updates that address this vulnerability. Workarounds that address this
vulnerability are not available." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-06-09 17:24:53 +0200 (Thu, 09 Jun 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_apic_web_detect.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_mandatory_keys( "cisco/application_policy_infrastructure_controller/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "1.0(1e)",
	 "1.0(1h)",
	 "1.0(1k)",
	 "1.0(1n)",
	 "1.0(2j)",
	 "1.0(2m)",
	 "1.0(3f)",
	 "1.0(3i)",
	 "1.0(3k)",
	 "1.0(3n)",
	 "1.0(4h)",
	 "1.0(4o)",
	 "1.1(0.920a)",
	 "1.1(1j)",
	 "1.1(3f)" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

