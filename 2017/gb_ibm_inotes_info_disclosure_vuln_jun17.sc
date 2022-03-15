CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811131" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-21 15:24:35 +0530 (Wed, 21 Jun 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_cve_id( "CVE-2017-1214" );
	script_bugtraq_id( 98993 );
	script_name( "IBM iNotes SVG Keylogger Information Disclosure Vulnerability - Jun17" );
	script_tag( name: "summary", value: "IBM iNotes is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a SVG keylogger error." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to send a malformed email to a victim, that when opened
  could cause an information disclosure." );
	script_tag( name: "affected", value: "IBM iNotes 9.0 and 9.0.1 prior to 9.0.1
  FP8 IF3, and 8.5, 8.5.1, 8.5.2 and 8.5.3 prior to 8.5.3 FP6 IF16." );
	script_tag( name: "solution", value: "Upgrade to IBM iNotes 9.0.1 FP8 IF3 or 8.5.3 FP6 IF16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg22002015" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hcl_domino_consolidation.sc" );
	script_mandatory_keys( "hcl/domino/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.0", test_version2: "9.0.1.8" )){
	fix = "9.0.1 Fix Pack 8 Interim Fix 3";
}
if(version_in_range( version: version, test_version: "8.5", test_version2: "8.5.3.6" )){
	fix = "8.5.3 Fix Pack 6 Interim Fix 16";
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

