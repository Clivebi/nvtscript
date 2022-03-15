CPE = "cpe:/a:microsoft:windows_live_messenger";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800332" );
	script_version( "2020-01-07T08:11:35+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 08:11:35 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5828" );
	script_bugtraq_id( 33125 );
	script_name( "Microsoft Windows Live Messenger Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://securityreason.com/securityalert/4862" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/499624/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ms_win_live_messenger_detect.sc" );
	script_mandatory_keys( "MS/LiveMessenger/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could lead to unauthorized information disclosure." );
	script_tag( name: "affected", value: "Microsoft, Windows Live Messenger Client version 8.5.1302.1018 and prior" );
	script_tag( name: "insight", value: "The vulnerability is due to field error in IPv4InternalAddrsAndPorts,
  IPv4Internal-Addrs and IPv4Internal-Port headers, which allow to discover
  IP address and port numbers via MSNP15 protocol used over a NAT session." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has Windows Live Messenger Client installed and is prone
  to Information Disclosure vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "8.5.1302.1018" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

