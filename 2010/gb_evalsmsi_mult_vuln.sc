if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800166" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 38116 );
	script_cve_id( "CVE-2010-0614", "CVE-2010-0615", "CVE-2010-0616", "CVE-2010-0617" );
	script_name( "evalSMSI multiple vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38478" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/56154" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/56157" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/56152" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1002-exploits/corelan-10-008-evalmsi.txt" );
	script_xref( name: "URL", value: "http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-008-evalmsi-2-1-03-multiple-vulnerabilities/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_evalsmsi_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "evalsmsi/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to view, edit and delete
  the backend database via SQL Injection or inject arbitrary web script or HTML
  via cross-site scripting attack." );
	script_tag( name: "affected", value: "evalSMSI version prior to 2.2.00 on all platforms." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Input passed to the 'query' parameter in ajax.php (when 'question' action
  is set), 'return' parameter in ajax.php and while writing comments to
  assess.php page (when 'continue_assess' action is set) is not properly
  sanitised before being used in SQL queries.

  - The passwords are stored in plaintext in the database, which allows
  attackers with database access to gain privileges." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to evalSMSI version 2.2.00 or later." );
	script_tag( name: "summary", value: "This host is running evalSMSI and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
evalSMSIPort = http_get_port( default: 80 );
evalSMSIVer = get_kb_item( "www/" + evalSMSIPort + "/evalSMSI" );
if(isnull( evalSMSIVer )){
	exit( 0 );
}
evalSMSIVer = eregmatch( pattern: "^(.+) under (/.*)$", string: evalSMSIVer );
if(evalSMSIVer[1] != NULL){
	if(version_is_less( version: evalSMSIVer[1], test_version: "2.0.00" )){
		report = report_fixed_ver( installed_version: evalSMSIVer[1], fixed_version: "2.0.00" );
		security_message( port: evalSMSIPort, data: report );
	}
}

