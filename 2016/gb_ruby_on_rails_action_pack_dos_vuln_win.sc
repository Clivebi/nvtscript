CPE = "cpe:/a:rubyonrails:rails";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809362" );
	script_version( "2020-07-14T14:33:06+0000" );
	script_cve_id( "CVE-2015-7581" );
	script_bugtraq_id( 81677 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-07-14 14:33:06 +0000 (Tue, 14 Jul 2020)" );
	script_tag( name: "creation_date", value: "2016-10-17 18:48:40 +0530 (Mon, 17 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Ruby on Rails Action Pack Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is running Ruby on Rails and is
  prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in
  'actionpack/lib/action_dispatch/routing/route_set.rb' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause a denial of service condition." );
	script_tag( name: "affected", value: "Ruby on Rails 4.x before 4.2.5.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Ruby on Rails 4.2.5.1,
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/01/25/14" );
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
if(IsMatchRegexp( version, "^4\\." )){
	if(version_is_less( version: version, test_version: "4.2.5.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.2.5.1", install_path: location );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

