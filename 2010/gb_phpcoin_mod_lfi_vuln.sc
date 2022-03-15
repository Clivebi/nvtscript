CPE = "cpe:/a:phpcoin:phpcoin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800736" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 38576 );
	script_cve_id( "CVE-2010-0953" );
	script_name( "phpCOIN 'mod' Parameter Local File Include Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpcoin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpcoin/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/56721" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/11641" );
	script_tag( name: "insight", value: "The flaw exists in 'mod.php' as it fails to properly sanitize user-supplied
  data, which allows remote attacker to include arbitrary files." );
	script_tag( name: "solution", value: "Upgrade to phpCOIN version 1.6.5 or higher" );
	script_tag( name: "summary", value: "This host is running phpCOIN and is prone to local file include
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive information
  and attacker can include arbitrary files." );
	script_tag( name: "affected", value: "phpCOIN version 1.2.1 and prior" );
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
if(version_is_less( version: vers, test_version: "1.2.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.6.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

