if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803679" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_cve_id( "CVE-2013-4621" );
	script_bugtraq_id( 60761 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-04 15:25:00 +0000 (Sat, 04 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-07-01 10:09:04 +0530 (Mon, 01 Jul 2013)" );
	script_name( "Magnolia CMS Access Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Jun/202" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/magnolia-cms-458-access-bypass" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 8080 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions, obtain sensitive information and perform unauthorized actions." );
	script_tag( name: "affected", value: "Magnolia CMS version 4.5.8 and prior" );
	script_tag( name: "insight", value: "The flaw allows non-administrator users to view contents from
  magnoliaPublic/.magnolia/log4j, /pages/logViewer.html,
  /pages/configuration.html, /pages/sendMail.html, /pages/permission.html,
  /pages/installedModulesList.html, and /pages/jcrUtils.html pages." );
	script_tag( name: "solution", value: "Upgrade to Magnolia CMS 4.5.9 or later." );
	script_tag( name: "summary", value: "This host is running Magnolia CMS and is prone to access bypass
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.magnolia-cms.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
req = http_get( item: NASLString( "/magnoliaPublic/.magnolia/pages/adminCentral.html" ), port: port );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, ">Magnolia" ) && ContainsString( res, ">Magnolia International Ltd" )){
	host = http_host_name( port: port );
	url = "/magnoliaPublic/.magnolia/pages/installedModulesList.html ";
	Postdata = "mgnlUserId=eric&mgnlUserPSWD=eric";
	sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Referer: http://", host, url, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( Postdata ), "\\r\\n\\r\\n", Postdata );
	rcvRes = http_send_recv( port: port, data: sndReq );
	if(rcvRes && ContainsString( rcvRes, ">Installed modules" ) && ContainsString( rcvRes, "Name" ) && ContainsString( rcvRes, "Description" )){
		security_message( port: port );
		exit( 0 );
	}
}

