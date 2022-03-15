if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802851" );
	script_version( "$Revision: 13803 $" );
	script_cve_id( "CVE-2012-2162" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-11 17:31:58 +0530 (Fri, 11 May 2012)" );
	script_name( "IBM WebSphere Application Server 'plugin-key.kdb' Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74900" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21591172" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21588312" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to gain sensitive
  information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS) 8.0 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error in the Plug-in, which uses unencrypted
  HTTP communication after expiration of the plugin-key.kdb password. Which
  allows remote attackers to sniff the network, or spoof arbitrary server
  and further perform a man-in-the-middle (MITM) attacks to obtain sensitive information." );
	script_tag( name: "summary", value: "The host is running IBM WebSphere Application Server and is prone to
  information disclosure vulnerability." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:ibm:websphere_application_server";
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "8.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

