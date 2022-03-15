if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120157" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:18:47 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-296)" );
	script_tag( name: "insight", value: "Stack-based buffer overflow in the chkNum function in lib/cgraph/scan.l in Graphviz 2.34.0 allows remote attackers to have unspecified impact via vectors related to a badly formed number and a long digit list. Stack-based buffer overflow in the yyerror function in lib/cgraph/scan.l in Graphviz 2.34.0 allows remote attackers to have unspecified impact via a long line in a dot file. Graphviz was recently reported to be affected by a buffer overflow vulnerability, which seem to have introduced in the fix for CVE-2014-0978 ." );
	script_tag( name: "solution", value: "Run yum update graphviz to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-296.html" );
	script_cve_id( "CVE-2014-1235", "CVE-2014-1236", "CVE-2014-0978" );
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
	if(!isnull( res = isrpmvuln( pkg: "graphviz-lua", rpm: "graphviz-lua~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-java", rpm: "graphviz-java~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-python", rpm: "graphviz-python~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-ruby", rpm: "graphviz-ruby~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-guile", rpm: "graphviz-guile~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-php54", rpm: "graphviz-php54~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-tcl", rpm: "graphviz-tcl~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-gd", rpm: "graphviz-gd~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-doc", rpm: "graphviz-doc~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-graphs", rpm: "graphviz-graphs~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-devel", rpm: "graphviz-devel~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz", rpm: "graphviz~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-debuginfo", rpm: "graphviz-debuginfo~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-perl", rpm: "graphviz-perl~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphviz-R", rpm: "graphviz-R~2.30.1~12.39.amzn1", rls: "AMAZON" ) )){
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

