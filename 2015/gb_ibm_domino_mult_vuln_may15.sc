CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805549" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-05-08 16:03:56 +0530 (Fri, 08 May 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2015-0117", "CVE-2015-0179" );
	script_bugtraq_id( 73911, 73913 );
	script_name( "IBM Domino Multiple Vulnerabilities - May15" );
	script_tag( name: "summary", value: "IBM Domino is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An overflow condition that is triggered as user-supplied input is not properly
    validated when handling a LDAP ModifyRequest packet.

  - An unspecified flaw in Notes System Diagnostic(NSD) that may allow a local attacker to gain elevated privileges." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to gain elevated privileges and to cause a stack-based buffer overflow,
  resulting in a denial of service or potentially allowing the execution of arbitrary code." );
	script_tag( name: "affected", value: "IBM Domino 8.5.x before 8.5.3 FP6 IF6 and 9.x before 9.0.1 FP3 IF1." );
	script_tag( name: "solution", value: "Upgrade to IBM Domino 8.5.3 FP6 IF6 or 9.0.1 FP3 IF1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21700029" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_hcl_domino_consolidation.sc" );
	script_mandatory_keys( "hcl/domino/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.5", test_version2: "8.5.3.6" )){
	fix = "8.5.3 FP6 IF6";
	VULN = TRUE;
}
if(version_in_range( version: version, test_version: "9.0", test_version2: "9.0.1.3" )){
	fix = "9.0.1 FP3 IF1";
	VULN = TRUE;
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

