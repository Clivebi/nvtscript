CPE = "cpe:/a:pidgin:pidgin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800424" );
	script_version( "$Revision: 12670 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-05 15:14:20 +0100 (Wed, 05 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0277" );
	script_name( "Pidgin MSN Protocol Plugin Denial Of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_pidgin_detect_lin.sc" );
	script_mandatory_keys( "Pidgin/Lin/Ver" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/01/07/2" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to cause a denial of service (memory corruption)
  or possibly have unspecified other impact via unknown vectors." );
	script_tag( name: "affected", value: "Pidgin version prior to 2.6.6 on Linux." );
	script_tag( name: "insight", value: "This issue is due to an error in 'slp.c' within the 'MSN protocol plugin'
  in 'libpurple' when processing MSN request." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.6.6 or later." );
	script_tag( name: "summary", value: "This host has Pidgin installed and is prone to Denial Of Service
  vulnerability" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: ver, test_version: "2.6.4" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.6.6" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

