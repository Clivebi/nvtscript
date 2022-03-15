CPE = "cpe:/o:geneko:router_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107262" );
	script_version( "2020-06-17T06:45:15+0000" );
	script_tag( name: "last_modification", value: "2020-06-17 06:45:15 +0000 (Wed, 17 Jun 2020)" );
	script_tag( name: "creation_date", value: "2017-11-17 14:42:26 +0700 (Fri, 17 Nov 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Geneko Routers Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_geneko_router_consolidation.sc" );
	script_mandatory_keys( "geneko/router/detected" );
	script_tag( name: "summary", value: "Geneko Router version 3.18.21 is vulnerable to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to a bug in the configuration backup process." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain the admin password." );
	script_tag( name: "affected", value: "Geneko Routers version up to and including 3.18.21." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://ssd-disclosure.com/ssd-advisory-geneko-routers-information-disclosure/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "3.18.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

