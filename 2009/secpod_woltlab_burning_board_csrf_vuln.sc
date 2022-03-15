CPE = "cpe:/a:woltlab:burning_board";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900937" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-7192" );
	script_name( "WoltLab Burning Board Cross-Site Request Forgery Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_woltlab_burning_board_detect.sc" );
	script_mandatory_keys( "WoltLabBurningBoard/detected" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/39990" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/487139/100/200/threaded" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to delete private messages by
  sending malicious input in the 'pmID' parameter in a delete action in a PM page." );
	script_tag( name: "affected", value: "WoltLab Burning Board version 3.x" );
	script_tag( name: "insight", value: "An error arises in index.php due to improper sanitization of
  user-supplied input which may allows remote attackers to hijack the users authentication." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WoltLab Burning Board and is prone to
  Cross-Site Request Forgery vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^3\\..+" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

