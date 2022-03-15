CPE = "cpe:/a:western_digital:sharespace";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812364" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_bugtraq_id( 54068 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2017-12-26 20:19:48 +0530 (Tue, 26 Dec 2017)" );
	script_name( "Western Digital ShareSpace WEB GUI Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_sharespace_web_detect.sc" );
	script_mandatory_keys( "WD/ShareSpace/detected" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Jun/309" );
	script_tag( name: "summary", value: "The host is running Western Digital ShareSpace
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted http GET request
  and check whether it is able to read the sensitive information or not." );
	script_tag( name: "insight", value: "The flaw exists due to an improper configuration
  of access rights of the configuration file config.xml" );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information. By directly
  accessing the config.xml file without authentication it is possible to obtain
  system's configuration data, which includes network settings, shared folder
  names, SMB users and hashed passwords, administrator's credentials, etc." );
	script_tag( name: "affected", value: "WD ShareSpace versions through 2.3.02
  (D and E series)." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!wdPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(http_vuln_check( port: wdPort, url: "/admin/config.xml", pattern: "<certificate", extra_check: make_list( "<key",
	 "<passwd>",
	 "<htusers>",
	 "<smblan",
	 "<nfsright",
	 "<emaillist",
	 "<sharename",
	 "<htpasswd" ), check_header: TRUE )){
	report = http_report_vuln_url( port: wdPort, url: "/admin/config.xml" );
	security_message( port: wdPort, data: report );
}
exit( 0 );

