CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105114" );
	script_version( "2021-03-01T15:07:09+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 15:07:09 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-11-07 12:40:00 +0100 (Fri, 07 Nov 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2013-4421", "CVE-2013-4434" );
	script_bugtraq_id( 62958, 62993 );
	script_name( "Dropbear SSH < 2013.59 Multiple Security Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 SCHUTZWERK GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dropbear_consolidation.sc" );
	script_mandatory_keys( "dropbear_ssh/detected" );
	script_tag( name: "summary", value: "Dropbear SSH is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The buf_decompress function in packet.c in Dropbear SSH Server before 2013.59
  allows remote attackers to cause a denial of service (memory consumption)
  via a compressed packet that has a large size when it is decompressed.

  - Dropbear SSH Server before 2013.59 generates error messages for a failed
  logon attempt with different time delays depending on whether the user account
  exists." );
	script_tag( name: "impact", value: "The flaws allows remote attackers to cause a denial of service
  or to discover valid usernames." );
	script_tag( name: "affected", value: "Versions prior to Dropbear SSH 2013.59 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for
  more information." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62958" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62993" );
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
if(int( ver[1] ) > 2013){
	exit( 99 );
}
if(version_is_less( version: ver[2], test_version: "59" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2013.59", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

