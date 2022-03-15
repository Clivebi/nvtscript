if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120727" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:21 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-738)" );
	script_tag( name: "solution", value: "Run yum update mysql55 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-738.html" );
	script_cve_id( "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0505", "CVE-2016-0600", "CVE-2016-0616", "CVE-2016-3452", "CVE-2016-0644", "CVE-2016-3477", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0640", "CVE-2016-3521", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0666", "CVE-2016-0651", "CVE-2016-0650", "CVE-2016-0598", "CVE-2016-0649", "CVE-2016-2047", "CVE-2016-5440", "CVE-2016-5444", "CVE-2016-0606", "CVE-2016-0648", "CVE-2016-0646", "CVE-2016-0546", "CVE-2016-0647", "CVE-2016-3615", "CVE-2016-0641" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "mysql55-libs", rpm: "mysql55-libs~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-debuginfo", rpm: "mysql55-debuginfo~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-bench", rpm: "mysql55-bench~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-embedded-devel", rpm: "mysql55-embedded-devel~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-test", rpm: "mysql55-test~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-devel", rpm: "mysql55-devel~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-server", rpm: "mysql55-server~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-mysql-config", rpm: "mysql55-mysql-config~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55-embedded", rpm: "mysql55-embedded~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql55", rpm: "mysql55~5.5.51~1.11.amzn1", rls: "AMAZON" ) )){
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

