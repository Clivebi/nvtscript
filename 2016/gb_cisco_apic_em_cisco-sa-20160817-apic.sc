CPE = "cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106189" );
	script_version( "$Revision: 12338 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-19 08:44:32 +0700 (Fri, 19 Aug 2016)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-1365" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Application Policy Infrastructure Controller Enterprise Module Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_apic_em_web_detect.sc" );
	script_mandatory_keys( "cisco/apic_em/version" );
	script_tag( name: "summary", value: "A vulnerability in the Grapevine update process of the Cisco Application
Policy Infrastructure Controller Enterprise Module (APIC-EM) could allow an authenticated, remote attacker
to execute arbitrary commands on the underlying operating system with the privileges of the root user." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input sanitization during
the Grapevine update process. An attacker could exploit this vulnerability by authenticating to the affected
system with administrative privileges and inserting arbitrary commands into an upgrade parameter." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to execute arbitrary commands on
the affected system with root-level privileges." );
	script_tag( name: "affected", value: "Cisco APIC-EM software release 1.0." );
	script_tag( name: "solution", value: "Cisco has released free software updates that address the vulnerability.
Check the advisory for further details." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-apic" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version == "1.0.10"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See vendor advisory." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

