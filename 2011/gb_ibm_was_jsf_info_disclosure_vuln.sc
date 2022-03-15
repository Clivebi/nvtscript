if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801998" );
	script_version( "$Revision: 13803 $" );
	script_cve_id( "CVE-2011-1368" );
	script_bugtraq_id( 50463 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-03 18:00:39 +0530 (Thu, 03 Nov 2011)" );
	script_name( "IBM WebSphere Application Server JSF Application Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/70168" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1PM45992" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg24030916" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21474220" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will let remote unauthorized attackers to access
  or view files or obtain sensitive information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server versions 8.x before 8.0.0.1." );
	script_tag( name: "insight", value: "The flaw is caused by improper handling of requests in 'JSF' applications.
  A remote attacker could gain unauthorized access to view files on the host." );
	script_tag( name: "solution", value: "Apply the latest Fix Pack (8.0.0.1 or later) or APAR PM45992." );
	script_tag( name: "summary", value: "The host is running IBM WebSphere Application Server and is prone
  to information disclosure vulnerability." );
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
if(version_is_equal( version: vers, test_version: "8.0.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.0.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

