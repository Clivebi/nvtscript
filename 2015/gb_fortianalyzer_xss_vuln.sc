CPE = "cpe:/h:fortinet:fortianalyzer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805640" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_cve_id( "CVE-2015-3620" );
	script_bugtraq_id( 74646 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-06-01 15:56:50 +0530 (Mon, 01 Jun 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fortinet FortiAnalyzer Reflected XSS Vulnerability (FG-IR-15-005)" );
	script_tag( name: "summary", value: "Fortinet FortiAnalyzer is prone to a reflected cross-site
  scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the vulnerability in the advanced dataset
  reports page in Fortinet FortiAnalyzer." );
	script_tag( name: "impact", value: "Successful exploitation will allow a context-dependent attacker
  to create a specially crafted request that would execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "Fortinet FortiAnalyzer version 5.0.0 through 5.0.10 and 5.2.0
  through 5.2.1." );
	script_tag( name: "solution", value: "Update to version 5.0.11 or
  5.2.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-15-005" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_dependencies( "gb_fortianalyzer_version.sc" );
	script_mandatory_keys( "fortianalyzer/version" );
	script_xref( name: "URL", value: "http://www.fortinet.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!fazVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: fazVer, test_version: "5.0.0", test_version2: "5.0.10" )){
	VULN = TRUE;
	fix = "5.0.11";
}
if(version_in_range( version: fazVer, test_version: "5.2.0", test_version2: "5.2.1" )){
	VULN = TRUE;
	fix = "5.2.2";
}
if(VULN){
	report = "Installed version: " + fazVer + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

