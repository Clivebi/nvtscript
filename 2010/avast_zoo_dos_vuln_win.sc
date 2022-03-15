CPE = "cpe:/a:avast:antivirus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102050" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_cve_id( "CVE-2007-1672" );
	script_bugtraq_id( 23823 );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Avast! Zoo Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_avast_av_detect_win.sc" );
	script_mandatory_keys( "avast/antivirus/detected" );
	script_tag( name: "solution", value: "Update to a newer version." );
	script_tag( name: "summary", value: "avast! antivirus before 4.7.981 allows remote attackers to
  cause a denial of service (infinite loop) via a Zoo archive
  with a direntry structure that points to a previous file." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "4.7.981" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less than or equal to 4.7.981", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

