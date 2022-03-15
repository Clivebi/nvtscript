if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120148" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:18:36 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-76)" );
	script_tag( name: "insight", value: "Multiple flaws were found in ImageMagick. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update ImageMagick to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-76.html" );
	script_cve_id( "CVE-2012-0259", "CVE-2012-0247", "CVE-2012-0248", "CVE-2010-4167", "CVE-2012-1798", "CVE-2012-0260" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-doc", rpm: "ImageMagick-doc~6.5.4.7~6.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-devel", rpm: "ImageMagick-devel~6.5.4.7~6.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-debuginfo", rpm: "ImageMagick-debuginfo~6.5.4.7~6.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-perl", rpm: "ImageMagick-perl~6.5.4.7~6.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-c++-devel", rpm: "ImageMagick-c++-devel~6.5.4.7~6.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick-c++", rpm: "ImageMagick-c++~6.5.4.7~6.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~6.5.4.7~6.12.amzn1", rls: "AMAZON" ) )){
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

