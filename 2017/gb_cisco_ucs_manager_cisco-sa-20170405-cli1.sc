CPE = "cpe:/a:cisco:unified_computing_system_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106733" );
	script_cve_id( "CVE-2017-6601", "CVE-2017-6602" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_name( "Cisco UCS Manager CLI Command Injection Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cli1" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cli2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the CLI of the Cisco Unified Computing System (UCS)
Manager could allow an authenticated, local attacker to perform a command injection attack." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation. An attacker could
exploit this vulnerability by injecting crafted command arguments into a vulnerable CLI command." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to read or write arbitrary files at the
user`s privilege level outside of the user`s path." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-07 15:01:11 +0200 (Fri, 07 Apr 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ucs_manager_detect.sc" );
	script_mandatory_keys( "cisco_ucs_manager/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "3.1(1k)A"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

