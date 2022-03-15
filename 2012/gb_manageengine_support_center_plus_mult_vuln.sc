if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802477" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-10-18 10:24:32 +0530 (Thu, 18 Oct 2012)" );
	script_name( "Zoho ManageEngine Support Center Plus Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22040/" );
	script_xref( name: "URL", value: "http://www.bugsearch.net/en/13746/manageengine-support-center-plus-7908-multiple-vulnerabilities.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 8080 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to upload
malicious code (backdoors/shells) or insert arbitrary HTML and script code,
which will be executed in a user's browser session in the context of an
affected site." );
	script_tag( name: "affected", value: "ManageEngine Support Center Plus 7.9 Upgrade Pack 7908 and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper checking of image extension when uploading the files. This will
  lead to uploading web site files which could be used for malicious actions.

  - An input passed to the 'fromCustomer' parameter via 'HomePage.do' script is
  not properly sanitised before being returned to the user.

  - An input passed to multiple parameters via 'WorkOrder.do' script is not
  properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Zoho ManageEngine Support Center Plus and is
prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
if(http_vuln_check( port: port, url: "/", pattern: ">ManageEngine SupportCenter Plus<", check_header: TRUE, extra_check: "ZOHO Corp", usecache: TRUE )){
	url = "/HomePage.do?fromCustomer=%27;alert(document.cookie);" + "%20var%20frompor=%27null";
	if(http_vuln_check( port: port, url: url, pattern: "';alert\\(document\\.cookie\\); var frompor='null", check_header: TRUE, extra_check: ">ManageEngine SupportCenter Plus</" )){
		security_message( port: port );
		exit( 0 );
	}
}

