if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120273" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:22:11 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-187)" );
	script_tag( name: "insight", value: "This update fixes several vulnerabilities in the MySQL database server. Information about these flaws can be found in the References section." );
	script_tag( name: "solution", value: "Run yum update mysql55 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-187.html" );
	script_cve_id( "CVE-2013-2375", "CVE-2013-2389", "CVE-2013-1544", "CVE-2013-1532", "CVE-2013-1521", "CVE-2013-2392", "CVE-2013-1506", "CVE-2013-2378", "CVE-2012-5614", "CVE-2013-2391", "CVE-2013-1548", "CVE-2013-1552", "CVE-2013-1531", "CVE-2013-1555" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "mysql55-embedded-devel", rpm: "mysql55-embedded-devel~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-common", rpm: "mysql55-common~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-embedded", rpm: "mysql55-embedded~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-devel", rpm: "mysql55-devel~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-debuginfo", rpm: "mysql55-debuginfo~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-libs", rpm: "mysql55-libs~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-bench", rpm: "mysql55-bench~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55", rpm: "mysql55~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-server", rpm: "mysql55-server~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-test", rpm: "mysql55-test~5.5.31~1.32.amzn1", rls: "AMAZON" ) )){
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

