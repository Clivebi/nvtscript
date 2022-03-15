CPE = "cpe:/a:cisco:application_policy_infrastructure_controller";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140305" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-17 08:59:24 +0700 (Thu, 17 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-6768" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Application Policy Infrastructure Controller Custom Binary Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_apic_web_detect.sc" );
	script_mandatory_keys( "cisco/application_policy_infrastructure_controller/installed" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "A vulnerability in the build procedure for certain executable system files
installed at boot time on Cisco Application Policy Infrastructure Controller (APIC) devices could allow an
authenticated, local attacker to gain root-level privileges." );
	script_tag( name: "insight", value: "The vulnerability is due to a custom executable system file that was built
to use relative search paths for libraries without properly validating the library to be loaded. An attacker could
exploit this vulnerability by authenticating to the device and loading a malicious library that can escalate the
privilege level." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to gain root-level privileges
and take full control of the device. The attacker must have valid user credentials to log in to the device." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170816-apic2" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "1.1(1j)",
	 "1.1(0.920a)",
	 "1.1(3f)",
	 "1.3(2f)",
	 "1.3(1)",
	 "1.3(2)",
	 "1.2.2",
	 "1.2(3)",
	 "1.2(2)",
	 "2.0(1)" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory." );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

