CPE = "cpe:/a:taskfreak:taskfreak%21";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103078" );
	script_version( "2021-10-01T12:59:49+0000" );
	script_tag( name: "last_modification", value: "2021-10-01 12:59:49 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2011-02-15 13:44:44 +0100 (Tue, 15 Feb 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "TaskFreak! <= 0.6.4 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_taskfreak_http_detect.sc" );
	script_mandatory_keys( "taskfreak/detected" );
	script_tag( name: "summary", value: "TaskFreak! is prone to multiple cross-site scripting (XSS)
  vulnerabilities because the application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  let attackers steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "TaskFreak! version 0.6.4 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46350" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-4990.php" );
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
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "0.6.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

