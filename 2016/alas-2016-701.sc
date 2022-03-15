if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120690" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:08 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-701)" );
	script_tag( name: "insight", value: "Multiple flaws were found in OpenSSL as used in MySQL 5.6. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update mysql56 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-701.html" );
	script_cve_id( "CVE-2016-0639", "CVE-2016-0647", "CVE-2016-0705", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0666", "CVE-2016-0648", "CVE-2016-0655", "CVE-2016-2047" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "mysql56-embedded", rpm: "mysql56-embedded~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-test", rpm: "mysql56-test~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-errmsg", rpm: "mysql56-errmsg~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-devel", rpm: "mysql56-devel~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-server", rpm: "mysql56-server~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-debuginfo", rpm: "mysql56-debuginfo~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-libs", rpm: "mysql56-libs~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-common", rpm: "mysql56-common~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-embedded-devel", rpm: "mysql56-embedded-devel~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56-bench", rpm: "mysql56-bench~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql56", rpm: "mysql56~5.6.30~1.15.amzn1", rls: "AMAZON" ) )){
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

