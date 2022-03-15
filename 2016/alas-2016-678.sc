if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120668" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_tag( name: "creation_date", value: "2016-03-31 08:02:11 +0300 (Thu, 31 Mar 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-678)" );
	script_tag( name: "insight", value: "An out-of-bounds read flaw was found in the parsing of GIF files using GraphicsMagick." );
	script_tag( name: "solution", value: "Run yum update GraphicsMagick to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-678.html" );
	script_cve_id( "CVE-2015-8808" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
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
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-c++", rpm: "GraphicsMagick-c++~1.3.23~5.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-devel", rpm: "GraphicsMagick-devel~1.3.23~5.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.23~5.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-debuginfo", rpm: "GraphicsMagick-debuginfo~1.3.23~5.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-c++-devel", rpm: "GraphicsMagick-c++-devel~1.3.23~5.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-perl", rpm: "GraphicsMagick-perl~1.3.23~5.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick-doc", rpm: "GraphicsMagick-doc~1.3.23~5.7.amzn1", rls: "AMAZON" ) )){
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

