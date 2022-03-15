CPE = "cpe:/h:cisco:web_security_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140310" );
	script_cve_id( "CVE-2017-6783" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_name( "Cisco Web Security Appliance SNMP Polling Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170816-csa" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in SNMP polling for the Cisco Web Security Appliance (WSA)
could allow an authenticated, remote attacker to discover confidential information about the appliances that
should be available only to an administrative user." );
	script_tag( name: "insight", value: "The vulnerability occurs because the appliances do not protect confidential
information at rest in response to Simple Network Management Protocol (SNMP) poll requests. An attacker could
exploit this vulnerability by doing a crafted SNMP poll request to the targeted security appliance." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to discover confidential information that
should be restricted, and the attacker could use this information to conduct additional reconnaissance. The
attacker must know the configured SNMP community string to exploit this vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-25 10:50:00 +0000 (Fri, 25 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-08-17 10:48:31 +0700 (Thu, 17 Aug 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wsa_version.sc" );
	script_mandatory_keys( "cisco_wsa/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "10.0.0-230" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

