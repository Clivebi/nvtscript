CPE = "cpe:/a:ilohamail:ilohamail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14633" );
	script_version( "2021-04-09T11:48:55+0000" );
	script_tag( name: "last_modification", value: "2021-04-09 11:48:55 +0000 (Fri, 09 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "OSVDB", value: "7402" );
	script_name( "IlohaMail Contacts Deletion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Web application abuses" );
	script_dependencies( "ilohamail_detect.sc" );
	script_mandatory_keys( "ilohamail/detected" );
	script_tag( name: "solution", value: "Upgrade to IlohaMail version 0.7.9 or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of IlohaMail version
  0.7.9-RC2 or earlier. Such versions contain a flaw that enables an authenticated user to delete contacts
  belonging to any user provided the DB-based backend is used to store contacts. The flaw arises because
  ownership of 'delete_item' is not checked when deleting entries in include/save_contacts.MySQL.inc.

  ***** The Scanner has determined the vulnerability exists on the target

  ***** simply by looking at the version number of IlohaMail

  ***** installed there." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^0\\.([0-6].*|7\\.([0-8](-Devel)?|9-.+)$)" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.7.9", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

