CPE = "cpe:/a:pidgin:pidgin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900920" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2694" );
	script_bugtraq_id( 36071 );
	script_name( "Pidgin MSN SLP Packets Denial Of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_pidgin_detect_lin.sc" );
	script_mandatory_keys( "Pidgin/Lin/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36384" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=34" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2303" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code, corrupt memory
  and cause the application to crash." );
	script_tag( name: "affected", value: "Pidgin version prior to 2.5.9 on Linux." );
	script_tag( name: "insight", value: "An error in the 'msn_slplink_process_msg()' function while processing
  malformed MSN SLP packets which can be exploited to overwrite an
  arbitrary memory location." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.5.9." );
	script_tag( name: "summary", value: "This host has Pidgin installed and is prone to Denial of Service
  vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
ver = get_app_version( cpe: CPE );
if(version_is_less( version: ver, test_version: "2.5.9" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.5.9" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

