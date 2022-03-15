CPE = "cpe:/a:rubyonrails:rails";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807380" );
	script_version( "2020-07-14T14:33:06+0000" );
	script_cve_id( "CVE-2016-6316" );
	script_bugtraq_id( 92430 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-07-14 14:33:06 +0000 (Tue, 14 Jul 2020)" );
	script_tag( name: "creation_date", value: "2016-10-13 14:29:55 +0530 (Thu, 13 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Ruby on Rails Action View Cross Site Scripting Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is running Ruby on Rails and is
  prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the Text declared as
  'HTML safe' when passed as an attribute value to a tag helper will not have
  quotes escaped which can lead to an XSS attack." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to inject arbitrary web script or HTML via crafted parameters." );
	script_tag( name: "affected", value: "Ruby on Rails 3.x before 3.2.22.3,
  Ruby on Rails 4.x before 4.2.7.1 and
  Ruby on Rails 5.x before 5.0.0.1 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Ruby on Rails 3.2.22.3 or 4.2.7.1 or
  5.0.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2016/q3/260" );
	script_xref( name: "URL", value: "https://groups.google.com/forum/#!msg/rubyonrails-security/I-VWr034ouk/gGu2FrCwDAAJ" );
	script_xref( name: "URL", value: "http://weblog.rubyonrails.org/2016/8/11/Rails-5-0-0-1-4-2-7-2-and-3-2-22-3-have-been-released" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rails_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "rails/detected", "Host/runs_unixoide" );
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
if( IsMatchRegexp( version, "^(3\\.)" ) ){
	if(version_is_less( version: version, test_version: "3.2.22.3" )){
		fix = "3.2.22.3";
		VULN = TRUE;
	}
}
else {
	if( IsMatchRegexp( version, "^(4\\.)" ) ){
		if(version_is_less( version: version, test_version: "4.2.7.1" )){
			fix = "4.2.7.1";
			VULN = TRUE;
		}
	}
	else {
		if(IsMatchRegexp( version, "^(5\\.)" )){
			if(version_is_less( version: version, test_version: "5.0.0.1" )){
				fix = "5.0.0.1";
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

