if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100394" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)" );
	script_bugtraq_id( 12429 );
	script_cve_id( "CVE-2005-0338" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Savant Web Server Remote Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/12429" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_savant_webserver_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "savant/webserver/detected" );
	script_tag( name: "summary", value: "A remote buffer-overflow vulnerability affects Savant Web Server. This
  issue occurs because the application fails to validate the length of
  user-supplied strings before copying them into finite process buffers." );
	script_tag( name: "impact", value: "A remote attacker may leverage this issue to execute arbitrary code
  with the privileges of the affected webserver. This issue may
  facilitate unauthorized access or privilege escalation." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
CPE = "cpe:/a:savant:savant_webserver";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Will Not Fix", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

