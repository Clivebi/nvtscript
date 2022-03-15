CPE = "cpe:/a:apache:rave";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803180" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-1814" );
	script_bugtraq_id( 58455 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-14 16:32:56 +0530 (Thu, 14 Mar 2013)" );
	script_name( "Apache Rave User Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/82758" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24744/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120769/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Mar/127" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/525982/30/0/threaded" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_rave_detect.sc" );
	script_mandatory_keys( "ApacheRave/installed" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain sensitive
  information about all user accounts via the offset parameter." );
	script_tag( name: "affected", value: "Apache Rave versions 0.11 to 0.20" );
	script_tag( name: "insight", value: "The flaw is due to error in handling of User RPC API, returns the full user
  object, including the salted and hashed password." );
	script_tag( name: "solution", value: "Upgrade to Apache Rave 0.20.1 or later." );
	script_tag( name: "summary", value: "The host is running Apache Rave and is prone to information
  disclosure vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^0\\." )){
	if(version_in_range( version: vers, test_version: "0.11", test_version2: "0.20" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "0.11 - 0.20" );
		security_message( port: port, data: report );
	}
}

