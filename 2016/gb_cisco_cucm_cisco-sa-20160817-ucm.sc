CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106190" );
	script_version( "$Revision: 12149 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-19 10:22:15 +0700 (Fri, 19 Aug 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-6364" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Unified Communications Manager Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_cucm_version.sc" );
	script_mandatory_keys( "cisco/cucm/version" );
	script_tag( name: "summary", value: "A vulnerability in the User Data Services (UDS) Application Programming
Interface (API) for Cisco Unified Communications Manager could allow an unauthenticated, remote attacker to
view confidential information that should require authentication." );
	script_tag( name: "insight", value: "The vulnerability is due to improper authentication controls for
certain information returned by the UDS API. An attacker could exploit this vulnerability by accessing the UDS
API." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to view certain information that is
confidential and should require authentication to retrieve via the UDS API." );
	script_tag( name: "affected", value: "Cisco Unified Communications Manager version 11.5" );
	script_tag( name: "solution", value: "Cisco has released software updates that address this vulnerability." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-ucm" );
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
version = str_replace( string: version, find: "-", replace: "." );
if(version == "11.5.0.98000.486"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See vendor advisory." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

