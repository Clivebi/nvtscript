CPE = "cpe:/a:pandasecurity:panda_gold_protection";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107091" );
	script_version( "2019-05-17T10:45:27+0000" );
	script_cve_id( "CVE-2014-3450" );
	script_tag( name: "last_modification", value: "2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "creation_date", value: "2016-11-18 09:18:47 +0100 (Fri, 18 Nov 2016)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Privilege Escalation in Panda Gold Protection 2014 CVE-2014-3450 (Windows)" );
	script_xref( name: "URL", value: "http://www.anti-reversing.com/cve-2014-3450-privilege-escalation-in-panda-security/" );
	script_xref( name: "URL", value: "https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-3450/" );
	script_tag( name: "qod", value: "30" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_panda_prdts_detect.sc" );
	script_mandatory_keys( "Panda/GoldProtection/Ver" );
	script_tag( name: "affected", value: "Panda Gold Protection v7.01.01" );
	script_tag( name: "insight", value: "As the USERS group has write permissions over the folder where the PSEvents.exe
process is located, it is possible to execute malicious code as Local System." );
	script_tag( name: "solution", value: "Install Panda Hotfix for this vulnerability, see the vendor advisory." );
	script_tag( name: "summary", value: "This host is running Panda Products and is prone to a Privilege
Escalation Vulnerability." );
	script_tag( name: "impact", value: "This vulnerability allows for privilege escalation on the local system.." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_equal( version: vers, test_version: "7.01.01" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

