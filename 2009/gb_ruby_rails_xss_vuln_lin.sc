CPE = "cpe:/a:rubyonrails:rails";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801078" );
	script_version( "2020-07-14T14:24:25+0000" );
	script_tag( name: "last_modification", value: "2020-07-14 14:24:25 +0000 (Tue, 14 Jul 2020)" );
	script_tag( name: "creation_date", value: "2009-12-09 07:52:52 +0100 (Wed, 09 Dec 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4214" );
	script_bugtraq_id( 37142 );
	script_name( "Ruby on Rails 'strip_tags' Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rails_consolidation.sc" );
	script_mandatory_keys( "rails/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37446" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1023245" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3352" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/11/27/2" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site or
  steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Ruby on Rails version before 2.3.5." );
	script_tag( name: "insight", value: "This issue is due to the error in 'strip_tagi()' function which is
  not properly escaping non-printable ascii characters." );
	script_tag( name: "solution", value: "Update to Ruby on Rails version 2.3.5 or later." );
	script_tag( name: "summary", value: "The host is running Ruby on Rails, which is prone to Cross Site
  Scripting Vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.3.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

