CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800759" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)" );
	script_cve_id( "CVE-2010-1586" );
	script_bugtraq_id( 39676 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "HP System Management Homepage (SMH) 'RedirectUrl' URI Redirection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58107" );
	script_xref( name: "URL", value: "https://h20392.www2.hp.com/portal/swdepot/displayProductInfo.do?productNumber=SysMgmtWeb" );
	script_xref( name: "URL", value: "http://yehg.net/lab/pr0js/advisories/hp_system_management_homepage_url_redirection_abuse" );
	script_tag( name: "insight", value: "Input data passed to the 'RedirectUrl' parameter in 'red2301.html'
  is not  being properly validated." );
	script_tag( name: "solution", value: "Upgrade HP System Management Homepage version to 6.2 or later" );
	script_tag( name: "summary", value: "This host is running HP System Management Homepage (SMH) and is prone
  to  URL redirection vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to redirect
  to his choice of malicious site via the trusted vulnerable SMH url or aid in
  phishing attacks." );
	script_tag( name: "affected", value: "HP System Management Homepage (SMH) version 2.x." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.hp.com/servers/manage/smh" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.0", test_version2: "2.2.9.3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

