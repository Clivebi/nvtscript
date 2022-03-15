if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10718" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2889 );
	script_cve_id( "CVE-2001-0821" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "DCShop exposes sensitive files" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securiteam.com/unixfocus/5RP0N2K4KE.html" );
	script_tag( name: "solution", value: "1. Rename following directories to something hard to guess:

  - Data

  - User_carts

  - Orders

  - Auth_data

  2. Make these changes to dcshop.setup and dcshop_admin.setup.

  - In dcshop.setup, modify:

  $datadir = '$cgidir/Data'

  $cart_dir = '$cgidir/User_carts'

  $order_dir = '$cgidir/Orders'

  - In dcshop_admin.setup, modify:

  $password_file_dir = '$path/Auth_data'

  3. Rename dcshop.setup and dcshop_admin.setup to something difficult to guess.
  For example, dcshop_4314312.setup and dcshop_admin_3124214.setup

  4. Edit dcshop.cgi, dcshop_admin.cgi, and dcshop_checkout.cgi and modify the
  require statement for dcshop.setup and dcshop_admin.setup. That is:

  - In dcshop.cgi, modify

  require '$path/dcshop.setup'

  so that it uses new setup file. For example,

  require '$path/dcshop_4314312.setup'

  - In dcshop_admin.cgi, modify

  require '$path/dcshop.setup'

  require '$path/dcshop_admin.setup'

  so that it uses new setup file. For example,

  require '$path/dcshop_4314312.setup'

  require '$path/dcshop_admin_3124214.setup'

  - In dcshop_checkout.cgi, modify

  require '$path/dcshop.setup'

  so that it uses new setup file. For example,

  require '$path/dcshop_4314312.setup'

  5. Save following file as index.html and upload it to your
  /cgi-bin/dcshop directory, thereby hiding directory listing. On
  NT servers, you may have to rename this file to default.htm.

  This page show 'Internal Server Error' so it is not an error page...
  it's just an index.html file to HIDE directories.

  6. Replace your current files with above files." );
	script_tag( name: "summary", value: "We detected a vulnerable version of the DCShop CGI.
  This version does not properly protect user and credit card information.
  It is possible to access files that contain administrative passwords,
  current and pending transactions and credit card information (along with name,
  address, etc)." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
program[0] = "/dcshop.pl";
program[1] = "/dcshop.cgi";
orders[0] = "/Orders/orders.txt";
orders[1] = "/orders/orders.txt";
Auth[0] = "/Auth_data/auth_user_file.txt";
Auth[1] = "/auth_data/auth_user_file.txt";
unsafe_url_count = 0;
for dir in nasl_make_list_unique( http_cgi_dirs( port: port ), "/dcshop", "/DCshop" ) {
	if(dir == "/"){
		dir = "";
	}
	for(j = 0;program[j];j++){
		url = NASLString( dir, program[j] );
		if(http_is_cgi_installed_ka( item: url, port: port )){
			unsafe_url_count = 0;
			for(k = 0;orders[k];k++){
				orders_url = NASLString( dir, orders[k] );
				success = http_is_cgi_installed_ka( item: orders_url, port: port );
				if(success){
					unsafe_urls[unsafe_url_count] = NASLString( "DCShop orders file: ", orders_url );
					unsafe_url_count = unsafe_url_count + 1;
				}
			}
			flag = 0;
			for(k = 0;Auth[k];k++){
				auth_url = NASLString( dir, Auth[k] );
				success = http_is_cgi_installed_ka( item: auth_url, port: port );
				if(success){
					flag = 1;
					unsafe_urls[unsafe_url_count] = NASLString( "DCShop authentication file: ", auth_url );
					unsafe_url_count = unsafe_url_count + 1;
				}
			}
		}
	}
}
if(unsafe_url_count > 0){
	data = NASLString( "\\n\\n\\nThe following files are affected:\\n\\n" );
	for(i = 0;i < unsafe_url_count;i++){
		data = NASLString( data, unsafe_urls[i], "\\n" );
	}
	security_message( port: port, data: data );
	exit( 0 );
}
exit( 99 );

