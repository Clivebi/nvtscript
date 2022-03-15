if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901199" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2011-0439", "CVE-2011-0440" );
	script_bugtraq_id( 47033 );
	script_name( "Mahara Cross Site Scripting and Cross Site Request Forgery Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43858" );
	script_xref( name: "URL", value: "http://mahara.org/interaction/forum/topic.php?id=3205" );
	script_xref( name: "URL", value: "http://mahara.org/interaction/forum/topic.php?id=3206" );
	script_xref( name: "URL", value: "http://mahara.org/interaction/forum/topic.php?id=3208" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mahara_detect.sc" );
	script_mandatory_keys( "mahara/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Mahara versions 1.2.x before 1.2.7 and 1.3.x before 1.3.4." );
	script_tag( name: "insight", value: "- The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests. This can be exploited to delete blog posts by
  tricking a logged in administrative user into visiting a malicious web site.

  - Certain input passed via Pieform select box options is not properly sanitised before being displayed to the
    user. This can be exploited to insert arbitrary HTML and script code." );
	script_tag( name: "solution", value: "Upgrade to Mahara version 1.2.7, 1.3.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Mahara is prone to multiple cross-site scripting and cross-site request forgery
  vulnerabilities." );
	exit( 0 );
}
CPE = "cpe:/a:mahara:mahara";
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
if(version_in_range( version: version, test_version: "1.3.0", test_version2: "1.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.2.0", test_version2: "1.2.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

