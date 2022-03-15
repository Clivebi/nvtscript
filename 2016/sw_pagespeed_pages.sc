if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111076" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-01-16 16:00:00 +0100 (Sat, 16 Jan 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "PageSpeed Modules (mod_pagespeed/ngx_pagespeed) Admin Pages accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script attempts to identify Admin Pages of the
  PageSpeed Modules (mod_pagespeed/ngx_pagespeed)" );
	script_tag( name: "vuldetect", value: "Check the response if Admin Pages are enabled." );
	script_tag( name: "impact", value: "Based on the information shown an attacker might be able to gather additional info about
  the structure of the system and its applications." );
	script_tag( name: "affected", value: "Webservers with a PageSpeed Module (mod_pagespeed/ngx_pagespeed) loaded and
  missing restrictions to the Admin Pages." );
	script_tag( name: "solution", value: "Restrict access to the Admin Pages for authorized systems only." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
adminPages = make_list( "/ngx_pagespeed_statistics",
	 "/ngx_pagespeed_global_statistics",
	 "/ngx_pagespeed_message",
	 "/mod_pagespeed_statistics",
	 "/mod_pagespeed_global_statistics",
	 "/mod_pagespeed_message",
	 "/pagespeed_console",
	 "/pagespeed_admin/",
	 "/pagespeed_global_admin/" );
report = "The following Admin pages were identified:\n";
port = http_get_port( default: 80 );
for url in adminPages {
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( buf, "<b>Pagespeed Admin</b>" )){
		report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		found = TRUE;
	}
}
if(found){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

