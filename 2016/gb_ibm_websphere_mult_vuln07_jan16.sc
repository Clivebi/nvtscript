CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806833" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0716", "CVE-2012-2170", "CVE-2012-0720", "CVE-2012-0717" );
	script_bugtraq_id( 52722, 53755, 52721, 52724 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-19 16:52:40 +0530 (Tue, 19 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Multiple Vulnerabilities -07 Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - The Application Snoop Servlet does not properly restrict access.

  - insufficient validation of requests by Administration Console.

  - A security bypass vulnerability when a certain SSLv2 configuration with
    client authentication is used." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attacker to bypass authentication, to inject arbitrary web script
  or HTML and to obtain sensitive information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  version 7.0 before 7.0.0.23" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.23 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21595172" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.22" )){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: "7.0.0.23" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

