CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800409" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-0321" );
	script_bugtraq_id( 33481 );
	script_name( "Apple Safari Malformed URI Remote DoS Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://lostmon.blogspot.com/2009/01/safari-for-windows-321-remote-http-uri.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Browser crash (application termination) could be the result when attacker
  executes arbitrary codes." );
	script_tag( name: "affected", value: "Apple Safari 3.2.1 and prior on Windows (Any)." );
	script_tag( name: "insight", value: "Malformed HTTP domain name can cause the safari web browser to an infinite
  loop which leads to memory violation when it tries to resolve the domain,
  or when it tries to write a section that contains unknown data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Apple Safari web browser and is prone
  to denial of service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
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
if(version_is_less_equal( version: vers, test_version: "3.525.27.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

