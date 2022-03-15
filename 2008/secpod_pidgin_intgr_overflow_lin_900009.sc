CPE = "cpe:/a:pidgin:pidgin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900009" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_bugtraq_id( 29956 );
	script_cve_id( "CVE-2008-2927" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_name( "Pidgin MSN SLP Message Integer Overflow Vulnerabilities (Linux)" );
	script_dependencies( "secpod_pidgin_detect_lin.sc" );
	script_mandatory_keys( "Pidgin/Lin/Ver" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=24" );
	script_tag( name: "affected", value: "Pidgin Version prior to 2.4.3 on Linux (All)." );
	script_tag( name: "insight", value: "The flaw is due to errors in the msn_slplink_process_msg
  function in libpurple/protocols/msnp9/slplink.c and libpurple/protocols/msn/slplink.c files,
  which fails to perform adequate boundary checks on user-supplied data." );
	script_tag( name: "summary", value: "The host is running Pidgin, which is prone to integer
  overflow vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Pidgin Version 2.4.3." );
	script_tag( name: "impact", value: "Remote attacker can execute arbitrary code by sending
  specially crafted SLP message with the privilege of a user." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "2.4.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.3", install_path: path );
	security_message( port: 0, data: report );
}
exit( 0 );

