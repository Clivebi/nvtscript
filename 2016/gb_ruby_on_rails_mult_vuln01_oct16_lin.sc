CPE = "cpe:/a:rubyonrails:rails";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809357" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-0752", "CVE-2016-0751", "CVE-2015-7576" );
	script_bugtraq_id( 81801, 81800, 81803 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-08 15:43:00 +0000 (Thu, 08 Aug 2019)" );
	script_tag( name: "creation_date", value: "2016-10-17 18:48:40 +0530 (Mon, 17 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Ruby on Rails Multiple Vulnerabilities-01 Oct16 (Linux)" );
	script_tag( name: "summary", value: "This host is running Ruby on Rails and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Directory traversal vulnerability in Action View.

  - The script 'actionpack/lib/action_dispatch/http/mime_type.rb' does not properly
    restrict use of the MIME type cache.

  - The http_basic_authenticate_with method in
    'actionpack/lib/action_controller/metal/http_authentication.rb' does not use a
    constant-time algorithm for verifying credentials." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to read arbitrary files by leveraging an application's unrestricted use
  of the render method, to cause a denial of service." );
	script_tag( name: "affected", value: "Ruby on Rails before 3.2.22.1,
  Ruby on Rails 4.0.x and 4.1.x before 4.1.14.1 and
  Ruby on Rails 4.2.x before 4.2.5.1 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Ruby on Rails 3.2.22.1 or 4.1.14.1 or
  4.2.5.1, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/01/25/10" );
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
if( version_is_less( version: version, test_version: "3.2.22.1" ) ){
	fix = "3.2.22.1";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( version, "^4\\." )){
		if(version_is_less( version: version, test_version: "4.1.14.1" )){
			fix = "4.1.14.1";
			VULN = TRUE;
		}
	}
}
if(IsMatchRegexp( version, "^4\\.2" )){
	if(version_is_less( version: version, test_version: "4.2.5.1" )){
		fix = "4.2.5.1";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

