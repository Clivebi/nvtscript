if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120346" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:24:17 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-437)" );
	script_tag( name: "insight", value: "crpyto/tls in Go 1.1 before 1.3.2, when SessionTicketsDisabled is enabled, allows man-in-the-middle attackers to spoof clients via unspecified vectors." );
	script_tag( name: "solution", value: "Run yum update golang to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-437.html" );
	script_cve_id( "CVE-2014-7189" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-bin-linux-386", rpm: "golang-pkg-bin-linux-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-netbsd-amd64", rpm: "golang-pkg-netbsd-amd64~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-linux-amd64", rpm: "golang-pkg-linux-amd64~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-freebsd-amd64", rpm: "golang-pkg-freebsd-amd64~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-vim", rpm: "golang-vim~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-darwin-amd64", rpm: "golang-pkg-darwin-amd64~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-netbsd-386", rpm: "golang-pkg-netbsd-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-openbsd-amd64", rpm: "golang-pkg-openbsd-amd64~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-linux-arm", rpm: "golang-pkg-linux-arm~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-openbsd-386", rpm: "golang-pkg-openbsd-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-plan9-amd64", rpm: "golang-pkg-plan9-amd64~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-darwin-386", rpm: "golang-pkg-darwin-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-plan9-386", rpm: "golang-pkg-plan9-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-netbsd-arm", rpm: "golang-pkg-netbsd-arm~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-windows-amd64", rpm: "golang-pkg-windows-amd64~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "emacs-golang", rpm: "emacs-golang~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-freebsd-arm", rpm: "golang-pkg-freebsd-arm~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-linux-386", rpm: "golang-pkg-linux-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-freebsd-386", rpm: "golang-pkg-freebsd-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-pkg-windows-386", rpm: "golang-pkg-windows-386~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-src", rpm: "golang-src~1.3.3~1.7.amzn1", rls: "AMAZON" ) )){
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

