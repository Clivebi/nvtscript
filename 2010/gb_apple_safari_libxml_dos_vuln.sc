CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801638" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)" );
	script_cve_id( "CVE-2010-4008" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Apple Safari libxml Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42175/" );
	script_xref( name: "URL", value: "http://blog.bkis.com/en/libxml2-vulnerability-in-google-chrome-and-apple-safari/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial
  of service." );
	script_tag( name: "affected", value: "Apple Safari version 5.0.2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error when traversing the XPath axis of
  certain XML files. This can be exploited to cause a crash when an application
  using the library processes a specially crafted XML file." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari 5.0.4 or later." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to denial of service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "5.33.18.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 5.0.4 (output of installed version differ from actual Safari version)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

