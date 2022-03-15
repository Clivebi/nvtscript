if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106669" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-03-17 15:44:20 +0700 (Fri, 17 Mar 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "b2evolution File Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "summary", value: "b2evolution is prone to a unrestricted file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unrestricted file upload vulnerability in 'file upload' modules in
  b2evolution CMS allows authenticated user to upload malicious code (shell), even though in the system has
  restricted extension (php)." );
	script_tag( name: "affected", value: "b2evolution 6.8.8." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://rungga.blogspot.co.id/2017/03/remote-file-upload-vulnerability-in.html" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

