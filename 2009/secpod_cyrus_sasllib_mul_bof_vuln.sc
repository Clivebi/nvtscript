if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900660" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-0688" );
	script_bugtraq_id( 34961 );
	script_name( "Cyrus SASL Remote Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35102" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/238019" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1313" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_cyrus_sasllib_detect.sc" );
	script_mandatory_keys( "Cyrus/SASL/Ver" );
	script_tag( name: "impact", value: "Successful exploits allow attackers to run arbitrary code and to crash an
  application that uses the library thus denying service to legitimate users." );
	script_tag( name: "affected", value: "Cyrus SASL version prior to 2.1.23" );
	script_tag( name: "insight", value: "An error in 'sasl_encode64' function within the lib/saslutil.c, as it fails
  to perform adequate boundary checks on user supplied data before copying the
  data to allocated memory buffers." );
	script_tag( name: "solution", value: "Upgrade to version 2.1.23 or later." );
	script_tag( name: "summary", value: "This host has installed Cyrus SASL library and is prone to Remote
  Buffer Overflow vulnerability" );
	exit( 0 );
}
require("version_func.inc.sc");
saslVer = get_kb_item( "Cyrus/SASL/Ver" );
if(!saslVer){
	exit( 0 );
}
if(version_is_less( version: saslVer, test_version: "2.1.23" )){
	report = report_fixed_ver( installed_version: saslVer, fixed_version: "2.1.23" );
	security_message( port: 0, data: report );
}

