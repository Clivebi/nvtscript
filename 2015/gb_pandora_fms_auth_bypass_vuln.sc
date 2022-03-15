CPE = "cpe:/a:artica:pandora_fms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805706" );
	script_version( "2020-02-10T05:20:28+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-10 05:20:28 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-06-23 10:58:30 +0530 (Tue, 23 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Pandora FMS Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Pandora
  FMS and is prone to authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the session is not being
  checked before the password is changed." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Pandora FMS 5.0 and 5.1." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/37255" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pandora_fms_detect.sc" );
	script_mandatory_keys( "pandora_fms/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "5.0" ) || version_is_equal( version: version, test_version: "5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

