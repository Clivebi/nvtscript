CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809820" );
	script_version( "2020-09-22T09:01:10+0000" );
	script_tag( name: "last_modification", value: "2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2016-11-25 17:07:04 +0530 (Fri, 25 Nov 2016)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2016-0282" );
	script_name( "IBM INotes and Domino Cross-site Scripting Vulnerability - Nov16" );
	script_tag( name: "summary", value: "IBM Domino is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute script in a victim's Web browser within the security context of the
  hosting Web site, once the URL is clicked." );
	script_tag( name: "affected", value: "IBM iNotes and Domino 8.5.x before 8.5.3 FP6 IF2." );
	script_tag( name: "solution", value: "Upgrade to IBM Domino 8.5.3 FP6 IF2." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21991722" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_in_range( version: version, test_version: "8.5", test_version2: "8.5.3.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.3 FP6 IF2" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

