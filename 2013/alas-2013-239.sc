if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120199" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:19:59 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-239)" );
	script_tag( name: "insight", value: "Heap-based buffer overflow in the fcgid_header_bucket_read function in fcgid_bucket.c in the mod_fcgid module before 2.3.9 for the Apache HTTP Server allows remote attackers to have an unspecified impact via unknown vectors." );
	script_tag( name: "solution", value: "Run yum update mod24_fcgid to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-239.html" );
	script_cve_id( "CVE-2013-4365" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "mod24_fcgid-debuginfo", rpm: "mod24_fcgid-debuginfo~2.3.9~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mod24_fcgid", rpm: "mod24_fcgid~2.3.9~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

