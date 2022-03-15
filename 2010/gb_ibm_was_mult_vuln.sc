CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801647" );
	script_version( "$Revision: 13803 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)" );
	script_cve_id( "CVE-2010-0784", "CVE-2010-4220" );
	script_bugtraq_id( 44875 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "IBM WebSphere Application Server (WAS) Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41722" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2595" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg27014463" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to conduct Cross-site scripting
  attacks and cause a Denial of Service." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server versions 7.0 before 7.0.0.13." );
	script_tag( name: "insight", value: "- A cross-site scripting vulnerability exists in the administrative console
  due to improper filtering on input values.

  - A cross-site scripting vulnerability exists in the Integrated Solution
  Console due to improper filtering on input values." );
	script_tag( name: "summary", value: "The host is running IBM WebSphere Application Server and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution", value: "Apply Fix Pack 13 for version 7.0 (7.0.0.13) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.0.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.0.12" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

