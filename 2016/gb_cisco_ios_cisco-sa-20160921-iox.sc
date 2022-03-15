CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106282" );
	script_cve_id( "CVE-2016-6414" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12363 $" );
	script_name( "Cisco IOS Software iox Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160921-iox" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 15.6(3.0q)M or later." );
	script_tag( name: "summary", value: "A vulnerability exists in the iox command in Cisco IOS Software that
could allow an authenticated, local attacker to perform command injection into the IOx Linux guest operating
system (GOS)." );
	script_tag( name: "insight", value: "This vulnerability is due to insufficient input validation of iox command
line arguments. An attacker could exploit this vulnerability by providing crafted options to the iox command." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to execute commands of their choice in
the Linux GOS." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-22 10:06:54 +0700 (Thu, 22 Sep 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_cisco_ios_get_version.sc" );
	script_mandatory_keys( "cisco_ios/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "15.6(1)T1"){
	report = report_fixed_ver( installed_version: version, fixed_version: "15.6(3.0q)M" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

