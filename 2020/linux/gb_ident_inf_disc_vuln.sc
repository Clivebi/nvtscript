if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100081" );
	script_version( "2020-10-19T07:53:22+0000" );
	script_tag( name: "last_modification", value: "2020-10-19 07:53:22 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-23 12:13:13 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "ident Service Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Useless services" );
	script_dependencies( "auth_enabled.sc" );
	script_mandatory_keys( "ident/detected" );
	script_tag( name: "summary", value: "Checks whether an ident service is exposed on the target host." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "The ident protocol is considered dangerous because it allows attackers to
  gain a list of usernames on a computer system which can later be used in attacks." );
	script_tag( name: "solution", value: "Disable the ident service." );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0629" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_kb_item( "ident/port" )){
	exit( 0 );
}
report = "An ident service was detected on the target system.";
security_message( data: report, port: port );
exit( 0 );

