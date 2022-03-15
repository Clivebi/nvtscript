CPE = "cpe:/a:cisco:identity_services_engine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107070" );
	script_cve_id( "CVE-2016-6453" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_version( "$Revision: 12051 $" );
	script_name( "Cisco Identity Services Engine SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-ise" );
	script_tag( name: "impact", value: "The vulnerability is due to insufficient controls on Structured Query Language (SQL) statements." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An exploit could allow the attacker to determine the presence of certain values in the database." );
	script_tag( name: "solution", value: "Cisco has released software updates that address this vulnerability" );
	script_tag( name: "summary", value: "A vulnerability in the web framework code of Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to execute arbitrary SQL commands on the database." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-10-27 11:19:11 +0530 (Thu, 27 Oct 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ise_version.sc" );
	script_mandatory_keys( "cisco_ise/version", "cisco_ise/patch" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!patch = get_kb_item( "cisco_ise/patch" )){
	exit( 0 );
}
if(version == "1.3.0.876"){
	if(int( patch ) <= 7){
		report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 0 );

