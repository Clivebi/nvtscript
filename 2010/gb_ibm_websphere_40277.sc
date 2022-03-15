if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100647" );
	script_version( "2020-05-14T13:01:46+0000" );
	script_tag( name: "last_modification", value: "2020-05-14 13:01:46 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2010-05-21 13:16:55 +0200 (Fri, 21 May 2010)" );
	script_bugtraq_id( 40322, 40325, 40321, 40277 );
	script_cve_id( "CVE-2010-0774", "CVE-2010-0775", "CVE-2010-0776", "CVE-2010-0777" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "IBM WebSphere Application Server Long Filename Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40277" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27007951" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58557" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "IBM WebSphere Application Server (WAS) is prone to an information-
  disclosure vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to access sensitive
  information that may aid in further attacks." );
	script_tag( name: "affected", value: "This issue affects WAS 6.0, 6.1 and 7.0." );
	script_tag( name: "solution", value: "For IBM WebSphere Application Server 7.0:

  Apply the latest Fix Pack (7.0.0.11 or later).

  For IBM WebSphere Application Server 6.1:

  Apply the latest Fix Pack (6.1.0.31 or later).

  For IBM WebSphere Application Server 6.0:

  Apply the latest Fix Pack (6.0.2.43 or later)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:ibm:websphere_application_server";
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "7", test_version2: "7.0.0.10" ) || version_in_range( version: vers, test_version: "6.1", test_version2: "6.1.0.30" ) || version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2.42" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

