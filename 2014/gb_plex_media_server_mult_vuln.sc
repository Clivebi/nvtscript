CPE = "cpe:/a:plex:plex_media_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805226" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-22 17:44:41 +0530 (Mon, 22 Dec 2014)" );
	script_cve_id( "CVE-2014-9181", "CVE-2014-9304" );
	script_bugtraq_id( 65881 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Plex Media Server Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Plex Media
  Server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors are due to:

  - An error in '/system/proxy' which fails to validate pre-authentication user requests.

  - Input appended to the URL after 'manage', 'web' and 'resources' is not properly sanitised before being used
    to read files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to disclose certain
  sensitive information and bypass certain security restrictions." );
	script_tag( name: "affected", value: "Plex Media Server versions 0.9.9.2.374-aa23a69 and prior." );
	script_tag( name: "solution", value: "Upgrade to Plex Media Server version 0.9.9.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57205" );
	script_xref( name: "URL", value: "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140228-1_Plex_Media_Server_Authentication_bypass_local_file_disclosure_v10.txt" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_plex_media_server_remote_detect.sc" );
	script_mandatory_keys( "plex_media_server/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "0.9.9.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.9.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

