CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800506" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:N/A:N" );
	script_cve_id( "CVE-2009-0123" );
	script_bugtraq_id( 33234 );
	script_name( "Apple Safari RSS Feed Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/366491.php" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47917" );
	script_xref( name: "URL", value: "http://brian.mastenbrook.net/display/27" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful remote exploitation can potentially be exploited to gain access
  to sensitive information and launch other attacks." );
	script_tag( name: "affected", value: "Apple Safari 3.1.2 and prior on Windows." );
	script_tag( name: "insight", value: "Flaw is due an error generated in safari web browser while handling feed,
  feeds and feedsearch URL types for RSS feeds." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Apple Safari web browser which is prone
  to remote file access vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "3.525.21.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

