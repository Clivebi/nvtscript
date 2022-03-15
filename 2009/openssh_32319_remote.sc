CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100153" );
	script_version( "2019-05-22T07:58:25+0000" );
	script_cve_id( "CVE-2008-5161" );
	script_bugtraq_id( 32319 );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_tag( name: "last_modification", value: "2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_name( "OpenSSH CBC Mode Information Disclosure Vulnerability" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/32319" );
	script_tag( name: "impact", value: "Successful exploits will allow attackers to obtain four bytes of plaintext from
  an encrypted session." );
	script_tag( name: "affected", value: "Versions prior to OpenSSH 5.2 are vulnerable. Various versions of SSH Tectia
  are also affected." );
	script_tag( name: "insight", value: "The flaw is due to the improper handling of errors within an SSH session
  encrypted with a block cipher algorithm in the Cipher-Block Chaining 'CBC' mode." );
	script_tag( name: "solution", value: "Upgrade to OpenSSH 5.2 or later." );
	script_tag( name: "summary", value: "The host is installed with OpenSSH and is prone to information
  disclosure vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "5.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

