if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120642" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_tag( name: "creation_date", value: "2016-02-11 07:16:49 +0200 (Thu, 11 Feb 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-652)" );
	script_tag( name: "insight", value: "The ConnectionExists function in lib/url.c in libcurl before 7.47.0 does not properly re-use NTLM-authenticated proxy connections, which might allow remote attackers to authenticate as other users via a request, a similar issue to CVE-2014-0015 . (CVE-2016-0755 )" );
	script_tag( name: "solution", value: "Run yum update curl to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-652.html" );
	script_cve_id( "CVE-2016-0755", "CVE-2014-0015" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-17 01:29:00 +0000 (Wed, 17 Oct 2018)" );
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
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel", rpm: "libcurl-devel~7.40.0~8.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.40.0~8.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debuginfo", rpm: "curl-debuginfo~7.40.0~8.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl", rpm: "libcurl~7.40.0~8.54.amzn1", rls: "AMAZON" ) )){
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

