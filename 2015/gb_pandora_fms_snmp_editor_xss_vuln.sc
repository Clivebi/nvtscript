CPE = "cpe:/a:artica:pandora_fms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805709" );
	script_version( "2020-02-10T05:20:28+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-10 05:20:28 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-06-25 15:15:45 +0530 (Thu, 25 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Pandora FMS SNMP Editor XSS Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Pandora
  FMS and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to the SNMP trap editor does
  not validate input to the 'oid' and 'custom_oid' parameters before returning
  it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser
  session within the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "Pandora FMS 5.1 SP1." );
	script_tag( name: "solution", value: "As a workaround provide secure restriction
  or filtering of the OID and customer OID input fields. Encode and parse the
  input field context to prevent persistent execution of script code through the
  vulnerable snmp editor module." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2015/Jan/84" );
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
if(ContainsString( version, "5.1SP1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Workaround", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

