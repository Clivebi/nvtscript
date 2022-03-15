CPE = "cpe:/a:apache:couchdb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105903" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_name( "CouchDB Directory Traversal Vulnerability" );
	script_bugtraq_id( 57313 );
	script_cve_id( "CVE-2012-5641" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57313" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/81240" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Jan/81" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-04-28 11:20:26 +0700 (Mon, 28 Apr 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_couchdb_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 5984 );
	script_mandatory_keys( "couchdb/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Directory traversal vulnerability on MobchiWeb/CouchDB resulting
  in information disclosure." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 1.0.4, 1.1.2, 1.2.1 or later." );
	script_tag( name: "insight", value: "On Windows systems there is a directory traversal vulnerability in the
  partition2 function in mochiweb_util.erl in MochiWeb before 2.4.0, as used in Apache
  CouchDB allows remote attackers to read arbitrary files via a ..\\ (dot dot backslash)
  in the default URI." );
	script_tag( name: "affected", value: "CouchDB Version 1.0.3, 1.1.1, 1.2.0 on Windows" );
	script_tag( name: "impact", value: "A remote attacker could retrieve in binary form any CouchDB database,
  including the _users or _replication databases, or any other file that the user account
  used to run CouchDB might have read access to on the local filesystem." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if( revcomp( a: vers, b: "1.0.4" ) < 0 ){
		report = "Installed version: " + vers + "\nFixed version:     1.0.4";
	}
	else {
		if( ( revcomp( a: vers, b: "1.1.2" ) < 0 ) && ( revcomp( a: vers, b: "1.1.0" ) >= 0 ) ){
			report = "Installed version: " + vers + "\nFixed version:     1.1.2";
		}
		else {
			if(revcomp( a: vers, b: "1.2.0" ) == 0){
				report = "Installed version: " + vers + "\nFixed version:     1.2.1";
			}
		}
	}
}
if(report){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

