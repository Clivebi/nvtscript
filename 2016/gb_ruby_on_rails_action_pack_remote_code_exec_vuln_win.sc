CPE = "cpe:/a:rubyonrails:rails";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809352" );
	script_version( "2020-07-14T14:33:06+0000" );
	script_cve_id( "CVE-2016-2098" );
	script_bugtraq_id( 83725 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-07-14 14:33:06 +0000 (Tue, 14 Jul 2020)" );
	script_tag( name: "creation_date", value: "2016-10-14 18:40:26 +0530 (Fri, 14 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Ruby on Rails Action Pack Remote Code Execution Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is running Ruby on Rails and is
  prone to remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper sanitization of
  user supplied inputs to the 'render' method in a controller or view by
  'Action Pack'." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to control the arguments of the render method in a controller or a view,
  resulting in the possibility of executing arbitrary ruby code." );
	script_tag( name: "affected", value: "Ruby on Rails before 3.2.22.2,
  Ruby on Rails 4.x before 4.1.14.2 and
  Ruby on Rails 4.2.x before 4.2.5.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Ruby on Rails 3.2.22.2 or 4.1.14.2 or
  4.2.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2016/dsa-3509" );
	script_xref( name: "URL", value: "https://groups.google.com/forum/message/raw?msg=rubyonrails-security/ly-IH-fxr_Q/WLoOhcMZIAAJ" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rails_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "rails/detected", "Host/runs_windows" );
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
VULN = FALSE;
if( version_is_less( version: version, test_version: "3.2.22.2" ) ){
	fix = "3.2.22.2";
	VULN = TRUE;
}
else {
	if( IsMatchRegexp( version, "^(4\\.1)" ) ){
		if(version_is_less( version: version, test_version: "4.1.14.2" )){
			fix = "4.1.14.2";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( version, "^(4\\.2)" )){
			if(version_is_less( version: version, test_version: "4.2.5.2" )){
				fix = "4.2.5.2";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

