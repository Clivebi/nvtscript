if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902537" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)" );
	script_cve_id( "CVE-2011-1334" );
	script_bugtraq_id( 48446 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Cybozu Products Mail System Images Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45043" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN54074460/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000046.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cybozu_products/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Cybozu Office version 6

  Cybozu Dezie versions before 6.1

  Cybozu MailWise versions before 3.1

  Cybozu Garoon versions 2.0.0 through 2.1.3" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of unspecified input related to
  downloading images from the mail system, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to Cybozu Garoon version 2.5.0, Cybozu Office version 7
  Cybozu Dezie version 6.1, Cybozu Mailwise version 3.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Cybozu Office, Cybozu Garoon, Cybozu Dezie or
  Cybozu MailWise and is prone to cross site scripting vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "CybozuOffice" )){
	if(IsMatchRegexp( vers, "^6\\.*" )){
		security_message( port: port );
		exit( 0 );
	}
}
if(vers = get_version_from_kb( port: port, app: "CybozuGaroon" )){
	if(version_in_range( version: vers, test_version: "2.0.0", test_version2: "2.1.3" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "2.0.0 - 2.1.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(vers = get_version_from_kb( port: port, app: "CybozuDezie" )){
	if(version_is_less( version: vers, test_version: "6.1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "6.1" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(vers = get_version_from_kb( port: port, app: "CybozuMailWise" )){
	if(version_is_less( version: vers, test_version: "3.1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.1" );
		security_message( port: port, data: report );
	}
}

