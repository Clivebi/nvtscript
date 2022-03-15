CPE = "cpe:/a:wikiwebhelp:wiki_web_help";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100860" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-10-19 12:49:22 +0200 (Tue, 19 Oct 2010)" );
	script_bugtraq_id( 44152 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Wiki Web Help Insecure Cookie Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44152" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_wwh_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "WWH/installed" );
	script_tag( name: "summary", value: "Wiki Web Help is prone to an authentication-bypass vulnerability
  because it fails to adequately verify user-supplied input used for cookie-based authentication." );
	script_tag( name: "impact", value: "Attackers can exploit this vulnerability to gain administrative access
  to the affected application. This may aid in further attacks." );
	script_tag( name: "affected", value: "Wiki Web Help versions 0.3.3 and prior are vulnerable." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less( version: vers, test_version: "0.3.4" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

