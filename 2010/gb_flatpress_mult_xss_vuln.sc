CPE = "cpe:/a:flatpress:flatpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800284" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4461" );
	script_bugtraq_id( 37471 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "FlatPress Multiple Cross site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37938" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/10688" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "flatpress_detect.sc" );
	script_mandatory_keys( "flatpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attacker to execute arbitrary web
script or HTML code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "FlatPress version 0.909 and prior." );
	script_tag( name: "insight", value: "The flaws are due to error in 'contact.php', 'login.php' and 'search.php'
that fail to sufficiently sanitize user-supplied data via the PATH_INFO." );
	script_tag( name: "solution", value: "Upgrade to FlatPress version 0.909.1." );
	script_tag( name: "summary", value: "This host is running FlatPress and is prone to multiple Cross Site Scripting
vulnerabilities." );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/flatpress/files/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "0.909" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less than or equal to 0.909" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

