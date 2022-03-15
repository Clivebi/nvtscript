if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120421" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:25:58 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-448)" );
	script_tag( name: "insight", value: "The upstream patch for CVE-2014-8080  introduced checks against the REXML.entity_expansion_text_limit, but did not add restrictions to limit the number of expansions performed, i.e. checks against the REXML::Document.entity_expansion_limit.  As a consequence, even with the patch applied, a small XML document could cause REXML to use an excessive amount of CPU time.  High memory usage can be achieved using larger inputs." );
	script_tag( name: "solution", value: "Run yum update ruby20 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-448.html" );
	script_cve_id( "CVE-2014-8090" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "ruby20-libs", rpm: "ruby20-libs~2.0.0.598~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem20-io-console", rpm: "rubygem20-io-console~0.4.2~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby20", rpm: "ruby20~2.0.0.598~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem20-psych", rpm: "rubygem20-psych~2.0.0~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby20-devel", rpm: "ruby20-devel~2.0.0.598~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem20-bigdecimal", rpm: "rubygem20-bigdecimal~1.2.0~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygems20", rpm: "rubygems20~2.0.14~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby20-doc", rpm: "ruby20-doc~2.0.0.598~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby20-irb", rpm: "ruby20-irb~2.0.0.598~1.20.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygems20-devel", rpm: "rubygems20-devel~2.0.14~1.20.amzn1", rls: "AMAZON" ) )){
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

