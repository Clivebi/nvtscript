CPE = "cpe:/o:cisco:ios";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106250" );
	script_cve_id( "CVE-2016-6403" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_version( "2019-08-06T11:17:21+0000" );
	script_name( "Cisco IOS Software Data in Motion Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-ios-xe" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Data in Motion (DMo) application in Cisco IOS
software with the IOx feature set could allow an unauthenticated, remote attacker to cause a denial of service
condition in the DMo process." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation by the affected
software. An attacker could exploit this vulnerability by sending a specially crafted packet to the targeted
system." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a DoS condition on the targeted
system." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2019-08-06 11:17:21 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2016-09-16 11:26:46 +0700 (Fri, 16 Sep 2016)" );
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
if(version == "15.6(1)T"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

