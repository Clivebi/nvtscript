if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96183" );
	script_version( "2020-02-06T11:17:59+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-02-06 11:17:59 +0000 (Thu, 06 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-09-09 11:15:54 +0200 (Mon, 09 Sep 2013)" );
	script_name( "Windows file Checksums: Violations" );
	script_category( ACT_GATHER_INFO );
	script_family( "Policy" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "Policy/policy_file_checksums_win.sc" );
	script_mandatory_keys( "policy/file_checksums_win/started" );
	script_tag( name: "summary", value: "List Windows files with checksum violations." );
	script_tag( name: "solution", value: "Update or reconfigure the affected service / system / host according to the
  policy requirement." );
	script_tag( name: "qod", value: "98" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
md5fail = get_kb_list( "policy/file_checksums_win/md5_violation_list" );
sha1fail = get_kb_list( "policy/file_checksums_win/sha1_violation_list" );
if(md5fail || sha1fail){
	if(md5fail){
		md5fail = sort( md5fail );
	}
	if(sha1fail){
		sha1fail = sort( sha1fail );
	}
	report = "The following file checksums don\'t match:\n\n";
	report += "Filename|Result|Errorcode;\n";
	for fail in md5fail {
		report += fail + "\n";
	}
	for fail in sha1fail {
		report += fail + "\n";
	}
	security_message( port: 0, data: report );
}
exit( 0 );

