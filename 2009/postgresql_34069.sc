CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100158" );
	script_version( "2020-01-28T13:26:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)" );
	script_bugtraq_id( 34069 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "PostgreSQL Low Cost Function Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc" );
	script_mandatory_keys( "postgresql/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34069" );
	script_tag( name: "summary", value: "PostgreSQL is prone to an information-disclosure vulnerability." );
	script_tag( name: "impact", value: "Local attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks." );
	script_tag( name: "affected", value: "PostgreSQL 8.3.6 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
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
loc = infos["location"];
if(version_in_range( version: vers, test_version: "8.3", test_version2: "8.3.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

