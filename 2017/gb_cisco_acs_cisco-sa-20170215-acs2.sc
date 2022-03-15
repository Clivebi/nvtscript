CPE = "cpe:/a:cisco:secure_access_control_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106591" );
	script_cve_id( "CVE-2017-3840" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_name( "Cisco Secure Access Control System Open Redirect Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-acs2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web interface of the Cisco Secure Access Control
System (ACS) could allow an unauthenticated, remote attacker to redirect a user to a malicious web page." );
	script_tag( name: "insight", value: "The vulnerability is due to improper input validation of the parameters in
the HTTP request. An attacker could exploit this vulnerability by crafting an HTTP request that could cause the
web application to redirect the request to a specific malicious URL." );
	script_tag( name: "impact", value: "This vulnerability is known as an open redirect attack and is used in
phishing attacks to get users to visit malicious sites without their knowledge." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-25 01:29:00 +0000 (Tue, 25 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-02-16 11:20:11 +0700 (Thu, 16 Feb 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_acs_version.sc" );
	script_mandatory_keys( "cisco_acs/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "5.8(2.5)"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

