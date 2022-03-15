CPE = "cpe:/a:trueconf:trueconf";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106551" );
	script_version( "2019-09-09T13:48:19+0000" );
	script_tag( name: "last_modification", value: "2019-09-09 13:48:19 +0000 (Mon, 09 Sep 2019)" );
	script_tag( name: "creation_date", value: "2017-01-30 10:52:02 +0700 (Mon, 30 Jan 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TrueConf Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_trueconf_detect.sc" );
	script_mandatory_keys( "trueconf/installed" );
	script_tag( name: "summary", value: "TrueConf is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "TrueConf is prone to multiple vulnerabilities:

  - The administration interface allows users to perform certain actions via HTTP requests without performing any
validity checks to verify the requests. This can be exploited to perform certain actions with administrative
privileges if a logged-in user visits a malicious web site.

  - Input passed via the 'redirect_url' GET parameter is not properly verified before being used to redirect users.
This can be exploited to redirect a user to an arbitrary website e.g. when a user clicks a specially crafted
link to the affected script hosted on a trusted domain.

  - TrueConf also suffers from multiple stored, reflected and DOM XSS issues when input passed via several
parameters to several scripts is not properly sanitized before being returned to the user. This can be exploited
to execute arbitrary HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "TrueConf 4.3.7.12255 and 4.3.7.12219." );
	script_tag( name: "solution", value: "Upgrade to TrueConf version 4.3.8 or above." );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5393.php" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version == "4.3.7.12255" || version == "4.3.7.12219"){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

