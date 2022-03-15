if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16012" );
	script_version( "2020-04-03T11:05:30+0000" );
	script_tag( name: "last_modification", value: "2020-04-03 11:05:30 +0000 (Fri, 03 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 12044 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ArGoSoft Mail Server multiple flaws(2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_argosoft_mailserver_consolidation.sc" );
	script_mandatory_keys( "argosoft/mailserver/detected" );
	script_tag( name: "solution", value: "Upgrade to ArGoSoft 1.8.7.0 or newer." );
	script_tag( name: "summary", value: "There are multiple flaws in ArGoSoft WebMail interface which
  may allow an attacker to bypass authentication, inject HTML in the e-mails read by the users
  and even to read arbitrary files on that server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:argosoft:argosoft_mail_server";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.8.7.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.7.0" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

