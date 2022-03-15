CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105121" );
	script_version( "2021-03-01T15:07:09+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 15:07:09 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-11-19 07:00:00 +0100 (Wed, 19 Nov 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 8439 );
	script_name( "Dropbear SSH < 0.35 Username Remote Format String Buffer Overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 SCHUTZWERK GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dropbear_consolidation.sc" );
	script_mandatory_keys( "dropbear_ssh/detected" );
	script_tag( name: "summary", value: "Dropbear SSH is prone to a username remote format string buffer overflow." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The program fails to perform proper bounds checking
  resulting in a format string buffer overflow." );
	script_tag( name: "impact", value: "By attempting to log on to a Dropbear Server with a
  username containing a format specifier, a remote attacker can overwrite arbitrary memory
  addresses and execute arbitrary code resulting in a loss of integrity." );
	script_tag( name: "affected", value: "Versions prior to Dropbear SSH 0.35 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/8439" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/387/" );
	script_xref( name: "URL", value: "https://matt.ucc.asn.au/dropbear/CHANGES" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
ver = eregmatch( pattern: "^([0-9]+)\\.([0-9]+)", string: vers );
if(isnull( ver[2] )){
	exit( 0 );
}
if(int( ver[1] ) > 0){
	exit( 99 );
}
if(version_is_less( version: ver[2], test_version: "35" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.35", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

