if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120623" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-01-20 07:22:42 +0200 (Wed, 20 Jan 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-633)" );
	script_tag( name: "insight", value: "A denial of service flaw was found in the ldb_wildcard_compare() function of libldb. A remote attacker could send a specially crafted packet that, when processed by an application using libldb (for example the AD LDAP server in Samba), would cause that application to consume an excessive amount of memory and crash.A memory-read flaw was found in the way the libldb library processed LDB DN records with a null byte. An authenticated, remote attacker could use this flaw to read heap-memory pages from the server." );
	script_tag( name: "solution", value: "Run yum update libldb to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-633.html" );
	script_cve_id( "CVE-2015-3223", "CVE-2015-5330" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(!isnull( res = isrpmvuln( pkg: "pyldb", rpm: "pyldb~1.1.20~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pyldb-devel", rpm: "pyldb-devel~1.1.20~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~1.1.20~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb-debuginfo", rpm: "libldb-debuginfo~1.1.20~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ldb-tools", rpm: "ldb-tools~1.1.20~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb", rpm: "libldb~1.1.20~1.7.amzn1", rls: "AMAZON" ) )){
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

