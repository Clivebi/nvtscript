CPE = "cpe:/a:symantec:endpoint_protection";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806571" );
	script_version( "2019-07-05T08:56:43+0000" );
	script_cve_id( "CVE-2015-8113", "CVE-2015-6555", "CVE-2015-6554" );
	script_bugtraq_id( 77494, 77495, 77585 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 08:56:43 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-11-16 12:41:11 +0530 (Mon, 16 Nov 2015)" );
	script_name( "Symantec Endpoint Protection Multiple Vulnerabilities Nov15" );
	script_tag( name: "summary", value: "This host is installed with Symantec
  Endpoint Protection and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An untrusted search path flaw.

  - Multiple unspecified flaws in the management console." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attacker to gain privileges, and an unauthenticated, remote attacker to do
  OS command execution, Java code execution with elevated application privileges." );
	script_tag( name: "affected", value: "Symantec Endpoint Protection (SEP) before
  version 12.1-RU6-MP3" );
	script_tag( name: "solution", value: "Update to Symantec Endpoint Protection (SEP)
  version 12.1-RU6-MP3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.tenable.com/plugins/index.php?view=single&id=86873" );
	script_xref( name: "URL", value: "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20151109_00" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Symantec/Endpoint/Protection" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sepVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
sepType = get_kb_item( "Symantec/SEP/SmallBusiness" );
if(isnull( sepType ) && version_in_range( version: sepVer, test_version: "12.1", test_version2: "12.1.6465.6200" )){
	report = "Installed version: " + sepVer + "\n" + "Fixed version:     " + "12.1 RU6 MP3" + "\n";
	security_message( data: report );
	exit( 0 );
}

