CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140311" );
	script_cve_id( "CVE-2017-6785" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_name( "Cisco Unified Communications Manager Horizontal Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170816-ucm" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in configuration modification permissions validation for
Cisco Unified Communications Manager could allow an authenticated, remote attacker to perform a horizontal
privilege escalation where one user can modify another user's configuration." );
	script_tag( name: "insight", value: "The vulnerability is due to lack of proper Role Based Access Control (RBAC)
when certain user configuration changes are requested. An attacker could exploit this vulnerability by sending an
authenticated, crafted HTTP request to the targeted application." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to impact the integrity of the application
where one user can modify the configuration of another user's information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-24 16:41:00 +0000 (Thu, 24 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-08-17 10:57:29 +0700 (Thu, 17 Aug 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_cucm_version.sc" );
	script_mandatory_keys( "cisco/cucm/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
version = str_replace( string: version, find: "-", replace: "." );
affected = make_list( "10.5.2.10000.5",
	 "11.0.1.10000.10",
	 "11.5.1.10000.6" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

