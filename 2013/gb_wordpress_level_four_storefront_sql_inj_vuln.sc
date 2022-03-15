if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803449" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-03-26 15:01:02 +0530 (Tue, 26 Mar 2013)" );
	script_name( "WordPress Level Four Storefront Plugin SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120950/wplevelfourstorefront-sql.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-level-four-storefront-sql-injection" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject or
manipulate SQL queries in the back-end database, allowing for the manipulation
or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "WordPress Level Four Storefront Plugin" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input to
the getsortmanufacturers.php script via id parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WordPress Level Four Storefront
Plugin and is prone to sql injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
CPE = "cpe:/a:wordpress:wordpress";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/wp-content/plugins/levelfourstorefront/getsortmanufacturers.php?id=-1'[SQLi]--";
if(http_vuln_check( port: port, url: url, pattern: "mysql_query\\(\\).*getsortmanufacturers\\.php" )){
	security_message( port );
	exit( 0 );
}

