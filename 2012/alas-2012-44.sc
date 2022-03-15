if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120251" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:21:28 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-44)" );
	script_tag( name: "insight", value: "This update fixes several vulnerabilities in the MySQL database server. Information about these flaws can be found on the Oracle Critical Patch Update Advisory page, listed in the References section. (CVE-2011-2262, CVE-2012-0075, CVE-2012-0087, CVE-2012-0101, CVE-2012-0102, CVE-2012-0112, CVE-2012-0113, CVE-2012-0114, CVE-2012-0115, CVE-2012-0116, CVE-2012-0118, CVE-2012-0119, CVE-2012-0120, CVE-2012-0484, CVE-2012-0485, CVE-2012-0490, CVE-2012-0492 )These updated packages upgrade MySQL to version 5.1.61. Refer to the MySQL release notes for a full list of changes:" );
	script_tag( name: "solution", value: "Run yum update mysql to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-44.html" );
	script_cve_id( "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490", "CVE-2012-0075", "CVE-2012-0492", "CVE-2012-0087", "CVE-2012-0101", "CVE-2011-2262", "CVE-2012-0120" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "mysql-embedded-devel", rpm: "mysql-embedded-devel~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-test", rpm: "mysql-test~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-debuginfo", rpm: "mysql-debuginfo~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-embedded", rpm: "mysql-embedded~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-libs", rpm: "mysql-libs~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-server", rpm: "mysql-server~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-bench", rpm: "mysql-bench~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-devel", rpm: "mysql-devel~5.1.61~1.27.amzn1", rls: "AMAZON" ) )){
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

