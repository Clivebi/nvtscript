CPE = "cpe:/a:mcafee:asset_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804428" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-2587", "CVE-2014-2588" );
	script_bugtraq_id( 66302 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-17 11:25:02 +0530 (Thu, 17 Apr 2014)" );
	script_name( "McAfee Asset Manager Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running McAfee Asset Manager and is prone to directory traversal
and SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to:

  - The '/servlet/downloadReport' script not properly sanitizing user input,
  specifically path traversal style attacks supplied via the 'reportFileName'
  GET parameter.

  - The /jsp/reports/ReportsAudit.jsp script not properly sanitizing
  user-supplied input to the 'user' POST parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to disclose potentially sensitive
information and inject or manipulate SQL queries in the back-end database,
allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "McAfee Asset Manager version 6.6" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/32368" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125775" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Mar/325" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_mcafee_asset_manager_detect.sc" );
	script_mandatory_keys( "McAfee/Asset/Manager/installed" );
	script_require_ports( "Services/www", 443 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!mwgPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
mwgVer = get_app_version( cpe: CPE, port: mwgPort );
if(!mwgVer){
	exit( 0 );
}
if(version_is_equal( version: mwgVer, test_version: "6.6" )){
	security_message( port: mwgPort );
	exit( 0 );
}

