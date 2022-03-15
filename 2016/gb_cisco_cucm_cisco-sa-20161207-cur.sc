CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106442" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-08 13:24:06 +0700 (Thu, 08 Dec 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-04 14:43:00 +0000 (Wed, 04 Jan 2017)" );
	script_cve_id( "CVE-2016-9210" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Unified Communications Manager Unified Reporting Upload Tool Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_cucm_version.sc" );
	script_mandatory_keys( "cisco/cucm/version" );
	script_tag( name: "summary", value: "A vulnerability in the Cisco Unified Reporting upload tool accessed via
the Cisco Unified Communications Manager could allow an unauthenticated, remote attacker to modify arbitrary
files on the file system." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient client-side validation checks. An
attacker could exploit this vulnerability by submitting a malicious POST request to the affected system." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to implant arbitrary files onto the
affected system." );
	script_tag( name: "affected", value: "Cisco Unified Communications Manager version 11.5(1.11007.2)" );
	script_tag( name: "solution", value: "Cisco has released software updates that address this vulnerability." );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-cur" );
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
vers = str_replace( string: vers, find: "-", replace: "." );
if(version == "11.5.1.11007.2"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See vendor advisory." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

