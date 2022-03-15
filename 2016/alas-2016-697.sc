if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120686" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:12:02 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-697)" );
	script_tag( name: "insight", value: "It was discovered that Mercurial failed to properly check Git sub-repository URLs. A Mercurial repository that includes a Git sub-repository with a specially crafted URL could cause Mercurial to execute arbitrary code. (CVE-2016-3068 )The binary delta decoder in Mercurial before 3.7.3 allows remote attackers to execute arbitrary code via a (1) clone, (2) push, or (3) pull command, related to (a) a list sizing rounding error and (b) short records. (CVE-2016-3630 )It was discovered that the Mercurial convert extension failed to sanitize special characters in Git repository names. A Git repository with a specially crafted name could cause Mercurial to execute arbitrary code when the Git repository was converted to a Mercurial repository. (CVE-2016-3069 )" );
	script_tag( name: "solution", value: "Run yum update mercurial to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-697.html" );
	script_cve_id( "CVE-2016-3069", "CVE-2016-3068", "CVE-2016-3630" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "emacs-mercurial", rpm: "emacs-mercurial~3.5.2~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial-python27", rpm: "mercurial-python27~3.5.2~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial-common", rpm: "mercurial-common~3.5.2~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial-python26", rpm: "mercurial-python26~3.5.2~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial-debuginfo", rpm: "mercurial-debuginfo~3.5.2~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "emacs-mercurial-el", rpm: "emacs-mercurial-el~3.5.2~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mercurial", rpm: "mercurial~3.5.2~1.26.amzn1", rls: "AMAZON" ) )){
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

