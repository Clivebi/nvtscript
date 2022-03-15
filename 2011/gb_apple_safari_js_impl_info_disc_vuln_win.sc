CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802284" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_cve_id( "CVE-2010-5070" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2011-12-09 12:12:12 +0530 (Fri, 09 Dec 2011)" );
	script_name( "Apple Safari JavaScript Implementation Information Disclosure Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://w2spconf.com/2010/papers/p26.pdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain access to
  sensitive information and launch other attacks." );
	script_tag( name: "affected", value: "Apple Safari version 4." );
	script_tag( name: "insight", value: "The flaw is due to the JavaScript implementation is not properly
  restrict the set of values contained in the object returned by the
  getComputedStyle method, which allows remote attackers to obtain sensitive
  information about visited web pages." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to information disclosure vulnerability." );
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
if(version_in_range( version: vers, test_version: "5.26.12.2", test_version2: "5.31.22.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

