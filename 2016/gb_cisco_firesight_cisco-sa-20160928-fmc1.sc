CPE = "cpe:/a:cisco:firesight_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106302" );
	script_cve_id( "CVE-2016-6420" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:N/A:N" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_name( "Cisco FireSIGHT System Software Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-fmc1" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the web framework of the Cisco Firepower Management Center
running on Cisco FireSIGHT System Software could allow authenticated, remote attackers to elevate privileges
to access data outside their roles." );
	script_tag( name: "insight", value: "The vulnerability is due to improper authorization checks for authenticated
users of the system. An attacker could exploit this vulnerability by sending a crafted HTTP request to the
affected web page." );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to access sensitive information
for which they are not authorized by the Firepower Management Center." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-09-29 14:36:21 +0700 (Thu, 29 Sep 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firesight_management_center_version.sc", "gb_cisco_firesight_management_center_http_detect.sc" );
	script_mandatory_keys( "cisco_firesight_management_center/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "4.10.3",
	 "5.2.0",
	 "5.3.0",
	 "5.3.1",
	 "5.4.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

