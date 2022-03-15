if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120075" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:16:52 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-111)" );
	script_tag( name: "insight", value: "An input validation flaw, leading to a heap-based buffer overflow, was found in the way OpenJPEG handled the tile number and size in an image tile header. A remote attacker could provide a specially-crafted image file that, when decoded using an application linked against OpenJPEG, would cause the application to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2012-3358 )OpenJPEG allocated insufficient memory when encoding JPEG 2000 files from input images that have certain color depths. A remote attacker could provide a specially-crafted image file that, when opened in an application linked against OpenJPEG (such as image_to_j2k), would cause the application to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2009-5030 )" );
	script_tag( name: "solution", value: "Run yum update openjpeg to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-111.html" );
	script_cve_id( "CVE-2009-5030", "CVE-2012-3358" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "openjpeg", rpm: "openjpeg~1.3~8.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg-devel", rpm: "openjpeg-devel~1.3~8.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg-libs", rpm: "openjpeg-libs~1.3~8.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openjpeg-debuginfo", rpm: "openjpeg-debuginfo~1.3~8.5.amzn1", rls: "AMAZON" ) )){
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

