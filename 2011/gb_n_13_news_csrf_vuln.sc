if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801738" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)" );
	script_cve_id( "CVE-2011-0642" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "N-13 News Cross-Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42959" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64824" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16013/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_n_13_news_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "n-13/news/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  script code, perform cross-site scripting attacks, Web cache poisoning, and other malicious activities." );
	script_tag( name: "affected", value: "N-13 News version 3.4, 3.7 and 4.0" );
	script_tag( name: "insight", value: "The flaw is caused by an improper validation of user-supplied
  input by the 'admin.php' script, which allows remote attackers to send a
  specially crafted HTTP request to add an administrative user." );
	script_tag( name: "solution", value: "Upgrade to N-13 News version 4.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running N-13 News and is prone to Cross-Site
  Request Forgery vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
newsPort = http_get_port( default: 80 );
newsVer = get_version_from_kb( port: newsPort, app: "N-13/News" );
if(newsVer){
	if(version_is_equal( version: newsVer, test_version: "3.4" ) || version_is_equal( version: newsVer, test_version: "3.7" ) || version_is_equal( version: newsVer, test_version: "4.0" )){
		security_message( newsPort );
	}
}

