CPE = "cpe:/a:apple:quicktime";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801427" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)" );
	script_cve_id( "CVE-2010-1799" );
	script_bugtraq_id( 41962 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "QuickTime Player Streaming Debug Error Logging Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40729" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/40729" );
	script_xref( name: "URL", value: "http://telussecuritylabs.com/threats/show/FSC20100727-08" );
	script_xref( name: "URL", value: "http://en.community.dell.com/support-forums/virus-spyware/f/3522/t/19340212.aspx" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_apple_quicktime_detection_win_900124.sc" );
	script_mandatory_keys( "QuickTime/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a stack-based buffer
  overflow by tricking a user into viewing a specially crafted web page that
  references a SMIL file containing an overly long URL." );
	script_tag( name: "affected", value: "QuickTime Player version prior to 7.6.7." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error in 'QuickTimeStreaming.qtx' when
  constructing a string to write to a debug log file." );
	script_tag( name: "solution", value: "Upgrade to QuickTime Player version 7.6.7 or later." );
	script_tag( name: "summary", value: "The host is running QuickTime Player and is prone to buffer overflow
  vulnerability." );
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
if(version_is_less( version: vers, test_version: "7.6.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.6.7", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

