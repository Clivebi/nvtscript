CPE = "cpe:/a:cisco:application_policy_infrastructure_controller";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809051" );
	script_cve_id( "CVE-2015-6424" );
	script_bugtraq_id( 79410 );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-09-21 19:23:26 +0530 (Wed, 21 Sep 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Application Policy Infrastructure Controller Access Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is running Cisco
  Application Policy Infrastructure Controller and is prone to access bypass
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper
  implementation of access controls in the APIC system and an attacker could
  exploit this vulnerability by accessing the boot manager of the APIC." );
	script_tag( name: "impact", value: "Successful exploitation allows an
  unauthenticated, local attacker to access the APIC as the root user and
  perform root-level commands in single-user mode." );
	script_tag( name: "affected", value: "Cisco Application Policy Infrastructure
  Controller running software version 1.1(0.920a)" );
	script_tag( name: "solution", value: "Upgrade to Cisco Application Policy
  Infrastructure Controller software version as mentioned in vendor link." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151216-apic" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_apic_web_detect.sc" );
	script_mandatory_keys( "cisco/application_policy_infrastructure_controller/installed" );
	script_require_ports( "Services/www", 80, 443 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ciscoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: ciscoPort )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "1.1(0.920a)" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See vendor advisory" );
	security_message( port: ciscoPort, data: report );
	exit( 0 );
}

