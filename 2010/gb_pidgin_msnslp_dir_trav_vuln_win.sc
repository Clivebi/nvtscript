if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800421" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-0013" );
	script_name( "Pidgin MSN Custom Smileys File Disclosure Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_pidgin_detect_win.sc" );
	script_mandatory_keys( "Pidgin/Win/Ver" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=42" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to gain knowledge of sensitive information
  via directory traversal attacks." );
	script_tag( name: "affected", value: "Pidgin version prior to 2.6.4 on Windows." );
	script_tag( name: "insight", value: "This issue is due to an error in 'slp.c' within the 'MSN protocol plugin'
  in 'libpurple' when processing application/x-msnmsgrp2p MSN emoticon (aka custom smiley) request." );
	script_tag( name: "summary", value: "This host has Pidgin installed and is prone to File Disclosure
  vulnerability." );
	script_tag( name: "solution", value: "Update to Pidgin version 2.6.5." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:pidgin:pidgin";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.6.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.6.5", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

