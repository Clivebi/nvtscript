CPE = "cpe:/a:michael_dehaan:cobbler";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103515" );
	script_bugtraq_id( 53666 );
	script_cve_id( "CVE-2012-2395" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_name( "Cobbler Remote Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53666" );
	script_xref( name: "URL", value: "http://freshmeat.net/projects/cobbler" );
	script_xref( name: "URL", value: "https://bugs.launchpad.net/ubuntu/+source/cobbler/+bug/978999" );
	script_xref( name: "URL", value: "https://github.com/cobbler/cobbler/issues/141" );
	script_xref( name: "URL", value: "https://github.com/cobbler/cobbler/commit/6d9167e5da44eca56bdf42b5776097a6779aaadf" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-07-12 16:50:33 +0200 (Thu, 12 Jul 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_cobbler_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Cobbler/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Cobbler is prone to a remote command-injection vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary commands in the
context of the affected application." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "2.2.0" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Equal to 2.2.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

