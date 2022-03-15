CPE = "cpe:/a:openx:openx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800760" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)" );
	script_bugtraq_id( 37457 );
	script_cve_id( "CVE-2009-4830" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "OpenX Administrative Interface Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "OpenX_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openx/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37914" );
	script_xref( name: "URL", value: "http://forum.openx.org/index.php?showtopic=503454011" );
	script_tag( name: "insight", value: "The flaw is due to unspecified error related to the 'www/admin/'
  directory, which can be exploited to bypass authentication." );
	script_tag( name: "solution", value: "Upgrade to OpenX version 2.8.3 or later." );
	script_tag( name: "summary", value: "This host is running OpenX and is prone authentication bypass
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain administrative
  access to the affected application." );
	script_tag( name: "affected", value: "OpenX version 2.8.1 and 2.8.2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "2.8.1", test_version2: "2.8.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.8.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

