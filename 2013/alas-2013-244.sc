if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120123" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:18:06 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-244)" );
	script_tag( name: "insight", value: "An array index error, leading to a heap-based out-of-bounds buffer read flaw, was found in the way PostgreSQL performed certain error processing using enumeration types. An unprivileged database user could issue a specially crafted SQL query that, when processed by the server component of the PostgreSQL service, would lead to a denial of service (daemon crash) or disclosure of certain portions of server memory. (CVE-2013-0255 )A flaw was found in the way the pgcrypto contrib module of PostgreSQL (re)initialized its internal random number generator. This could lead to random numbers with less bits of entropy being used by certain pgcrypto functions, possibly allowing an attacker to conduct other attacks. (CVE-2013-1900 )" );
	script_tag( name: "solution", value: "Run yum update postgresql8 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-244.html" );
	script_cve_id( "CVE-2013-0255", "CVE-2013-1900" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-debuginfo", rpm: "postgresql8-debuginfo~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-devel", rpm: "postgresql8-devel~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-libs", rpm: "postgresql8-libs~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-server", rpm: "postgresql8-server~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8", rpm: "postgresql8~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-contrib", rpm: "postgresql8-contrib~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-pltcl", rpm: "postgresql8-pltcl~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-plpython", rpm: "postgresql8-plpython~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-test", rpm: "postgresql8-test~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-docs", rpm: "postgresql8-docs~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-plperl", rpm: "postgresql8-plperl~8.4.18~1.39.amzn1", rls: "AMAZON" ) )){
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

