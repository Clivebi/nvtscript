CPE = "cpe:/a:solucija:snews";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902544" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)" );
	script_cve_id( "CVE-2011-2706" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-16 17:39:00 +0000 (Thu, 16 Jan 2020)" );
	script_name( "sNews 'reorder' Functions Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Jul/296" );
	script_xref( name: "URL", value: "http://security.bkis.com/snews-1-7-1-xss-vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_snews_detect.sc" );
	script_mandatory_keys( "snews/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "sNews Version 1.7.1." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via 'reorder' functions of administrator, which allows attackers to execute
  arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running sNews and is prone to a cross site scripting
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "1.7.1" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

