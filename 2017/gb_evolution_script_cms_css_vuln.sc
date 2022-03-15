CPE = "cpe:/a:evolution:script";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107219" );
	script_version( "2019-10-23T10:55:06+0000" );
	script_tag( name: "last_modification", value: "2019-10-23 10:55:06 +0000 (Wed, 23 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-13 11:59:56 +0200 (Tue, 13 Jun 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Evolution Script CMS v5.3 - Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "Evolution Script CMS is vulnerable to Cross Site Scripting Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The cross site vulnerability is located in the 'status' parameter of the 'Ticket Support' module." );
	script_tag( name: "impact", value: "Remote attackers are able to inject own malicious script codes via GET method request." );
	script_tag( name: "affected", value: "Evolution Script CMS Version 5.3." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.

  A workaround is to parse or escape the status parameter content.
  Disallow the usage of special chars to prevent further script code injection attacks.
  Parse the ticket support content list and include an own exception-handling." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Jun/14" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_evolution_script_detect.sc" );
	script_mandatory_keys( "evolution_script/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: ver, test_version: "5.3" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

