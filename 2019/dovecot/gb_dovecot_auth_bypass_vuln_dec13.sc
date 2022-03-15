CPE = "cpe:/a:dovecot:dovecot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114168" );
	script_version( "2020-08-14T08:58:27+0000" );
	script_tag( name: "last_modification", value: "2020-08-14 08:58:27 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-18 12:56:28 +0100 (Wed, 18 Dec 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2013-6171" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dovecot < 2.2.7 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to an authentication bypass vulnerability." );
	script_tag( name: "insight", value: "Checkpassword-reply in Dovecot performs setuid operations to a user who
  is authenticating, which allows local users to bypass authentication and access virtual email accounts by
  attaching to the process and using a restricted file descriptor to modify account information in the response
  to the dovecot-auth server." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Dovecot versions before 2.2.7." );
	script_tag( name: "solution", value: "Update to version 2.2.7 or later." );
	script_xref( name: "URL", value: "https://www.dovecot.org/list/dovecot-news/2013-November/000264.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.2.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

