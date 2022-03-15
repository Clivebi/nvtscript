CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801226" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)" );
	script_cve_id( "CVE-2010-2429" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Splunk 'Referer' Header Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40187" );
	script_xref( name: "URL", value: "http://www.splunk.com/view/SP-CAAAFHY" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59517" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_require_ports( "Services/www", 8000 );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary web script
or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Splunk version 4.0 through 4.1.2" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input passed via
the 'Referer' header before being returned to the user within a HTTP 404 error message when using Internet
Explorer." );
	script_tag( name: "solution", value: "Upgrade to Splunk version 4.1.3  or later." );
	script_tag( name: "summary", value: "This host is running Splunk and is prone to Cross-Site Scripting
vulnerability." );
	script_xref( name: "URL", value: "http://www.splunk.com/download" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "4.0", test_version2: "4.1.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.1.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

