if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120217" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-25 11:17:59 +0300 (Fri, 25 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-597)" );
	script_tag( name: "insight", value: "An integer overflow flaw was found in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server or, potentially, execute arbitrary code with the privileges of the X.Org server. (CVE-2015-1802 )An integer truncation flaw was discovered in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server or, potentially, execute arbitrary code with the privileges of the X.Org server. (CVE-2015-1804 )A NULL pointer dereference flaw was discovered in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server. (CVE-2015-1803 )" );
	script_tag( name: "solution", value: "Run yum update libXfont to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-597.html" );
	script_cve_id( "CVE-2015-1804", "CVE-2015-1802", "CVE-2015-1803" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "libXfont-debuginfo", rpm: "libXfont-debuginfo~1.4.5~5.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXfont-devel", rpm: "libXfont-devel~1.4.5~5.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXfont", rpm: "libXfont~1.4.5~5.12.amzn1", rls: "AMAZON" ) )){
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

