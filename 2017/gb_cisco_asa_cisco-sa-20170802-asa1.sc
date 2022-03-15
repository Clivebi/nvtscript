CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140270" );
	script_cve_id( "CVE-2017-6765" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_name( "Cisco ASA WebVPN Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-asa1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based management interface of Cisco Adaptive
Security Appliance (ASA) could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS)
attack against a user of the web-based management interface of an affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient validation of user-supplied input
by the web-based management interface of an affected device. An attacker could exploit this vulnerability by
persuading a user of the interface to click a crafted link." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive browser-based information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-15 14:32:00 +0000 (Wed, 15 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-08-03 10:04:24 +0700 (Thu, 03 Aug 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
affected = make_list( "9.1.6.11",
	 "9.4.1.2" );
for af in affected {
	if(check_vers == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

