CPE = "cpe:/a:webmin:webmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812841" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-1937" );
	script_bugtraq_id( 47558 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2018-03-29 11:07:00 +0530 (Thu, 29 Mar 2018)" );
	script_name( "Webmin Cross-Site Scripting Vulnerability-02 Mar18 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Webmin and is
  prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because Webmin fails to
  properly filter HTML code from user-supplied input in the user's full name
  before displaying the input." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute an arbitrary script in victim's Web browser within the security
  context of the hosting Web site." );
	script_tag( name: "affected", value: "Webmin versions before 1.550 on Linux." );
	script_tag( name: "solution", value: "Upgrade to version 1.550 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://securitytracker.com/id?1025438" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "webmin.sc", "os_detection.sc" );
	script_mandatory_keys( "Host/runs_unixoide", "webmin/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: wport, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "1.550" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.550", install_path: path );
	security_message( port: wport, data: report );
	exit( 0 );
}
exit( 0 );

