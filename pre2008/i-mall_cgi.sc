if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15750" );
	script_version( "2020-08-25T06:50:30+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:50:30 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2275" );
	script_bugtraq_id( 10626 );
	script_xref( name: "OSVDB", value: "7461" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "i-mall.cgi" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script i-mall.cgi is installed. Some versions of
  this script are vulnerable to remote command exacution flaw, due to insuficient user
  input sanitization." );
	script_tag( name: "impact", value: "A malicious user can pass arbitrary shell commands
  on the remote server through this script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
http_check_remote_code( extra_dirs: make_list( "/i-mall" ), check_request: "/i-mall.cgi?p=|id|", check_result: "uid=[0-9]+.* gid=[0-9]+.*", command: "id" );
exit( 99 );

