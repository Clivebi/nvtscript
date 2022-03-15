CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800656" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-07-12 15:16:55 +0200 (Sun, 12 Jul 2009)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_cve_id( "CVE-2009-2420", "CVE-2009-2421" );
	script_name( "Apple Safari Denial Of Service Vulnerability - Jul09" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/504479" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "affected", value: "Apple Safari 3.2.3 on Windows." );
	script_tag( name: "insight", value: "The flaws are due to

  - Error in 'CFCharacterSetInitInlineBuffer' method in CoreFoundation.dll
  when processing high-bit character in a URL fragment for an unspecified protocol.

  - Error in implementing the file 'protocol handler' when processing vectors
  involving an unspecified HTML tag." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to Denial of Service vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary
  code or can even crash the browser." );
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
if(version_is_less_equal( version: vers, test_version: "3.525.29.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

