if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120655" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "creation_date", value: "2016-03-11 07:09:17 +0200 (Fri, 11 Mar 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-665)" );
	script_tag( name: "insight", value: "A defect in control channel input handling was discovered which can cause named to exit due to an assertion failure in sexpr.c or alist.c when a malformed packet is sent to named's control channel. If control channel input is accepted from the network (limited to localhost by default), an unauthenticated attacker could cause named to crash. (CVE-2016-1285 )An error when parsing signature records for DNAME records having specific properties can lead to named exiting due to an assertion failure in resolver.c or db.c. An attacker able to cause a server to make a query deliberately chosen to generate a malicious response can cause named to stop execution with an assertion failure, resulting in denial of service to clients. (CVE-2016-1286 )" );
	script_tag( name: "solution", value: "Run yum update bind to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-665.html" );
	script_cve_id( "CVE-2016-1286", "CVE-2016-1285" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-21 02:29:00 +0000 (Tue, 21 Nov 2017)" );
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
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.8.2~0.37.rc1.45.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.8.2~0.37.rc1.45.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.8.2~0.37.rc1.45.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.8.2~0.37.rc1.45.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.8.2~0.37.rc1.45.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chroot", rpm: "bind-chroot~9.8.2~0.37.rc1.45.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-sdb", rpm: "bind-sdb~9.8.2~0.37.rc1.45.amzn1", rls: "AMAZON" ) )){
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

