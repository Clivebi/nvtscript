CPE = "cpe:/a:moinmo:moinmoin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108327" );
	script_version( "$Revision: 12120 $" );
	script_cve_id( "CVE-2012-4404" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2018-02-12 10:47:19 +0100 (Mon, 12 Feb 2018)" );
	script_name( "MoinMoin 1.9 < 1.9.5 ACL Security Bug (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moinmoin_wiki_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "moinmoinWiki/installed", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://moinmo.in/SecurityFixes" );
	script_xref( name: "URL", value: "http://hg.moinmo.in/moin/1.9/rev/7b9f39289e16" );
	script_tag( name: "impact", value: "This issue may allow remote authenticated users with virtual group
  membership to be treated as a member of the group." );
	script_tag( name: "affected", value: "MoinMoin 1.9 through 1.9.4." );
	script_tag( name: "solution", value: "Update to version 1.9.5 or later. Please see the references for
  more information." );
	script_tag( name: "summary", value: "MoinMoin does not properly handle group names that contain virtual
  group names such as 'All, ' 'Known, ' or 'Trusted, '" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.9", test_version2: "1.9.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.9.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

