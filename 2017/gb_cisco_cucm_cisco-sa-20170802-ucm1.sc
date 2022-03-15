CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140276" );
	script_cve_id( "CVE-2017-6758" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:N/A:N" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_name( "Cisco Unified Communications Manager Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-ucm1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web framework of Cisco Unified Communications Manager
could allow an authenticated, remote attacker to access arbitrary files in the context of the web root directory
structure on an affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation by the affected
software." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by using directory traversal
techniques to read files in the web root directory structure on the Cisco Unified Communications Manager
filesystem." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-03 11:04:08 +0700 (Thu, 03 Aug 2017)" );
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
affected = make_list( "11.5.1.10000.6" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

