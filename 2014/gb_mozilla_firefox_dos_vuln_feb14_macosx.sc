CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804502" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2013-6167" );
	script_bugtraq_id( 62969 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-02-19 11:18:41 +0530 (Wed, 19 Feb 2014)" );
	script_name( "Mozilla Firefox Cookie Verification Denial of Service Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to improper handling of the browser.cookie cookie header." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to terminate a user's session on
  a website, which will not allow the attacker to log back in to the website until after the browser has been restarted." );
	script_tag( name: "affected", value: "Mozilla Firefox version 19.0 on Mac OS X." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q4/121" );
	script_xref( name: "URL", value: "http://redmine.lighttpd.net/issues/2188" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=858215" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: ffVer, test_version: "19.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

