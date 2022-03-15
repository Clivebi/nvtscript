if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120367" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:24:44 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-502)" );
	script_tag( name: "insight", value: "Multiple integer overflow flaws and an integer signedness flaw, leading to heap-based buffer overflows, were found in the way FreeType handled Mac fonts. If a specially crafted font file was loaded by an application linked against FreeType, it could cause the application to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2014-9673, CVE-2014-9674 )Multiple flaws were found in the way FreeType handled fonts in various formats. If a specially crafted font file was loaded by an application linked against FreeType, it could cause the application to crash or, possibly, disclose a portion of the application memory. (CVE-2014-9657, CVE-2014-9658, CVE-2014-9660, CVE-2014-9661, CVE-2014-9663, CVE-2014-9664, CVE-2014-9667, CVE-2014-9669, CVE-2014-9670, CVE-2014-9671, CVE-2014-9675 )" );
	script_tag( name: "solution", value: "Run yum update freetype to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-502.html" );
	script_cve_id( "CVE-2014-9663", "CVE-2014-9657", "CVE-2014-9661", "CVE-2014-9660", "CVE-2014-9667", "CVE-2014-9664", "CVE-2014-9669", "CVE-2014-9658", "CVE-2014-9674", "CVE-2014-9675", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9673" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "freetype-debuginfo", rpm: "freetype-debuginfo~2.3.11~15.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype-demos", rpm: "freetype-demos~2.3.11~15.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype", rpm: "freetype~2.3.11~15.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freetype-devel", rpm: "freetype-devel~2.3.11~15.14.amzn1", rls: "AMAZON" ) )){
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

