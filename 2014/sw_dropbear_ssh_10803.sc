CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105116" );
	script_version( "2021-03-01T15:07:09+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 15:07:09 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-11-14 12:00:00 +0100 (Fri, 14 Nov 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2004-2486" );
	script_bugtraq_id( 10803 );
	script_name( "Dropbear SSH < 0.43 DSS Verification Code Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 SCHUTZWERK GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dropbear_consolidation.sc" );
	script_mandatory_keys( "dropbear_ssh/detected" );
	script_tag( name: "summary", value: "Dropbear SSH is prone to a DSS verification code vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The DSS verification code in Dropbear SSH before 0.43
  frees uninitialized variables." );
	script_tag( name: "impact", value: "This flaw might allow remote attackers to gain access." );
	script_tag( name: "affected", value: "Versions prior to Dropbear SSH 0.43 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/10803" );
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
if(version_is_less( version: ver[2], test_version: "43" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.43", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

