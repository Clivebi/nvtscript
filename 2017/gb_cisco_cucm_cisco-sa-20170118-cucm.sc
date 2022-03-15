CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106524" );
	script_cve_id( "CVE-2017-3798" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_name( "Cisco Unified Communications Manager Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-cucm" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A cross-site scripting (XSS) filter bypass vulnerability in the web-based
management interface of Cisco Unified Communications Manager could allow an unauthenticated, remote attacker to
mount XSS attacks against a user of an affected device." );
	script_tag( name: "insight", value: "The vulnerability is due to a failure to properly call XSS filter subsystems
when a URL contains a certain parameter." );
	script_tag( name: "impact", value: "An attacker who can persuade an authenticated user of an affected device to
follow an attacker-provided link or visit an attacker-controlled website could exploit this vulnerability to
execute arbitrary code in the context of the affected site in the user's browser." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-26 01:29:00 +0000 (Wed, 26 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-01-19 10:01:26 +0700 (Thu, 19 Jan 2017)" );
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
if(version == "11.5.1.12000.1"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

