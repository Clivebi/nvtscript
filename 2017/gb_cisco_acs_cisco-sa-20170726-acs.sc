CPE = "cpe:/a:cisco:secure_access_control_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106993" );
	script_cve_id( "CVE-2017-6769" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_name( "Cisco Access Control System Stored Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-acs1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web-based management interface of the Cisco Secure
Access Control System (ACS) could allow an authenticated, remote attacker to conduct a stored cross-site scripting
(XSS) attack against a user of the web interface of the affected system." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation of user-supplied
values and a lack of encoding of user-supplied data." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by convincing a user to click a
malicious link." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-10 13:47:00 +0000 (Thu, 10 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-07-28 09:27:48 +0700 (Fri, 28 Jul 2017)" );
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
affected = make_list( "5.8(0.8)",
	 "5.8(1.5)" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

