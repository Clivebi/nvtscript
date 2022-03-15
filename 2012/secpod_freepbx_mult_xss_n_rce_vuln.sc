if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902823" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 52630 );
	script_cve_id( "CVE-2012-4869", "CVE-2012-4870" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-27 16:35:51 +0530 (Tue, 27 Mar 2012)" );
	script_name( "FreePBX Multiple Cross Site Scripting and Remote Command Execution Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48475" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48463" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74173" );
	script_xref( name: "URL", value: "http://www.freepbx.org/trac/ticket/5711" );
	script_xref( name: "URL", value: "http://www.freepbx.org/trac/ticket/5713" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18649" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111130/freepbx2100-exec.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_freepbx_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "freepbx/installed" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to steal cookie-based
  authentication credentials or execute arbitrary commands within the context
  of the affected application." );
	script_tag( name: "affected", value: "FreePBX versions 2.9.0 and 2.10.0" );
	script_tag( name: "insight", value: "Multiple flaws are caused by an,

  - Improper validation of user-supplied input by multiple scripts, which
    allows attacker to execute arbitrary HTML and script code on the user's
    browser session in the security context of an affected site.

  - Input passed to the 'callmenum' parameter in recordings/misc/callme_page.php
    (when 'action' is set to 'c') is not properly verified before being used.
    This can be exploited to inject and execute arbitrary shell commands." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is running FreePBX and is prone to multiple cross site
  scripting and remote command execution vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:freepbx:freepbx";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
urls = make_list( "/recordings/index.php?login='><script>alert(document.cookie)</script>",
	 "/panel/index_amp.php?context=\"<script>alert(document.cookie)</script>" );
for url in urls {
	if(http_vuln_check( port: port, url: dir + url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
		security_message( port: port );
		exit( 0 );
	}
}

