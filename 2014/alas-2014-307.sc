if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120528" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:28:38 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-307)" );
	script_tag( name: "insight", value: "A heap-based buffer overflow and a use-after-free flaw were found in the tiff2pdf tool. An attacker could use these flaws to create a specially crafted TIFF file that would cause tiff2pdf to crash or, possibly, execute arbitrary code. (CVE-2013-1960, CVE-2013-4232 )Multiple buffer overflow flaws were found in the gif2tiff tool. An attacker could use these flaws to create a specially crafted GIF file that could cause gif2tiff to crash or, possibly, execute arbitrary code. (CVE-2013-4231, CVE-2013-4243, CVE-2013-4244 )A flaw was found in the way libtiff handled OJPEG-encoded TIFF images. An attacker could use this flaw to create a specially crafted TIFF file that would cause an application using libtiff to crash. (CVE-2010-2596 )Multiple buffer overflow flaws were found in the tiff2pdf tool. An attacker could use these flaws to create a specially crafted TIFF file that would cause tiff2pdf to crash. (CVE-2013-1961 )" );
	script_tag( name: "solution", value: "Run yum update libtiff to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-307.html" );
	script_cve_id( "CVE-2010-2596", "CVE-2013-4244", "CVE-2013-4232", "CVE-2013-1960", "CVE-2013-4231", "CVE-2013-1961", "CVE-2013-4243" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~3.9.4~10.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-static", rpm: "libtiff-static~3.9.4~10.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-debuginfo", rpm: "libtiff-debuginfo~3.9.4~10.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~3.9.4~10.12.amzn1", rls: "AMAZON" ) )){
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

