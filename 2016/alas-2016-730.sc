if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120719" );
	script_version( "2020-05-14T09:33:44+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:18 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2020-05-14 09:33:44 +0000 (Thu, 14 May 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-730)" );
	script_tag( name: "insight", value: "curl and libcurl before 7.50.1 do not prevent TLS session resumption when the client certificate has changed, which allows remote attackers to bypass intended restrictions by resuming a session. (CVE-2016-5419 )curl and libcurl before 7.50.1 do not check the client certificate when choosing the TLS connection to reuse, which might allow remote attackers to hijack the authentication of the connection by leveraging a previously created connection with a different client certificate. (CVE-2016-5420 )libcurl before 7.50.1 allows attackers to control which connection is used or possibly have unspecified other impact via unknown vectors. (CVE-2016-5421 )" );
	script_tag( name: "solution", value: "Run yum update curl to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-730.html" );
	script_cve_id( "CVE-2016-5421", "CVE-2016-5420", "CVE-2016-5419" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(!isnull( res = isrpmvuln( pkg: "libcurl", rpm: "libcurl~7.40.0~8.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debuginfo", rpm: "curl-debuginfo~7.40.0~8.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel", rpm: "libcurl-devel~7.40.0~8.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.40.0~8.59.amzn1", rls: "AMAZON" ) )){
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

