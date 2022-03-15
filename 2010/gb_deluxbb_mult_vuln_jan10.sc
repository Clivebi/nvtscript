CPE = "cpe:/a:deluxebb:deluxebb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800436" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4465", "CVE-2009-4466", "CVE-2009-4467", "CVE-2009-4468" );
	script_bugtraq_id( 37448 );
	script_name( "DeluxeBB Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "deluxeBB_detect.sc" );
	script_mandatory_keys( "deluxebb/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54980" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54977" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54975" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/10598" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "DeluxeBB version 1.3 and prior." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Improper sanitization of user supplied input in the 'page' parameter in
  'misc.php'.

  - Improperly controlled computation in 'tools.php' that leads to a denial
  of service (CPU or memory consumption).

  - Web root with insufficient access control, which allows to obtain user and
  configuration information, log data, and gain administrative access via a
  direct request to scripts in 'templates/including', 'logs/cp.php', 'images/',
  'templates/deluxe/admincp/', 'templates/corporate/admincp/', 'logs/including'
  'templates/blue/admincp/', 'wysiwyg/', 'docs/', 'classes/', 'lang/' and 'settings/'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running DeluxeBB and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less_equal( version: version, test_version: "1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "WillNotFix" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

