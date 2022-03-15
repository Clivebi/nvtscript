if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801864" );
	script_version( "$Revision: 13803 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)" );
	script_cve_id( "CVE-2011-1312" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_name( "IBM WebSphere Application Server (WAS) Security Bypass Vulnerability - March 2011" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg27014463" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg24028875" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will let remote authenticated administrators to
  bypass intended access restrictions." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server versions 6.1.0.x before 6.1.0.31 and
  7.x before 7.0.0.15." );
	script_tag( name: "insight", value: "The flaw is due to an error in Administrative Console component
  which does not prevent modifications of the primary admin id, allows remote authenticated administrators to
  bypass intended access restrictions by mapping a 'user' or 'group' to an administrator role." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application Server version 7.0.0.15 or later." );
	script_tag( name: "summary", value: "The host is running IBM WebSphere Application Server and is prone
  to security bypass vulnerability." );
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
if(version_in_range( version: vers, test_version: "6.1", test_version2: "6.1.0.30" ) || version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.0.14" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.1.0.31/7.0.0.15" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

