CPE = "cpe:/a:awstats:awstats";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800151" );
	script_version( "$Revision: 14010 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-12-09 13:27:23 +0100 (Tue, 09 Dec 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-5080" );
	script_name( "AWStats awstats.pl XSS Vulnerability - Dec08" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=474396" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=495432" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=495432#21" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "awstats_detect.sc" );
	script_mandatory_keys( "awstats/installed" );
	script_tag( name: "affected", value: "AWStats 6.8 and earlier." );
	script_tag( name: "insight", value: "The flaw is due to query_string parameter in awstats.pl which is not
  properly sanitized before being returned to the user." );
	script_tag( name: "summary", value: "The host is running AWStats, which is prone to XSS Vulnerability." );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary HTML and script code
  in the context of an affected site." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
if(version_is_less_equal( version: version, test_version: "6.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

