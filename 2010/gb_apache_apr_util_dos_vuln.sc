if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801521" );
	script_version( "$Revision: 13573 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-11 12:25:59 +0100 (Mon, 11 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2010-10-07 09:42:58 +0200 (Thu, 07 Oct 2010)" );
	script_cve_id( "CVE-2010-1623" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 43673 );
	script_name( "Apache APR-util 'buckets/apr_brigade.c' Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apache_apr-utils_detect.sc" );
	script_mandatory_keys( "Apache/APR-Utils/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41701" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2556" );
	script_xref( name: "URL", value: "http://security-tracker.debian.org/tracker/CVE-2010-1623" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial of service
  (memory consumption) via unspecified vectors." );
	script_tag( name: "affected", value: "Apache APR-Utils version prior 1.3.10." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'apr_brigade_split_line()' function in
  'buckets/apr_brigade.c', which allows an attacker to cause a denial of service (memory consumption)." );
	script_tag( name: "summary", value: "The host is installed with Apache APR-Util and is prone to
  denial of service vulnerability." );
	script_tag( name: "solution", value: "Upgrade to APR-util version 1.3.10 or later." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
apruVer = get_kb_item( "Apache/APR-Utils/Ver" );
if(!apruVer){
	exit( 0 );
}
if(version_is_less( version: apruVer, test_version: "1.3.10" )){
	report = report_fixed_ver( installed_version: apruVer, fixed_version: "1.3.10" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

