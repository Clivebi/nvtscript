if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883057" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_cve_id( "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-22 02:00:38 +0000 (Wed, 22 May 2019)" );
	script_name( "CentOS Update for ruby CESA-2019:1235 centos7 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:1235" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-May/023315.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby'
  package(s) announced via the CESA-2019:1235 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ruby is an extensible, interpreted, object-oriented, scripting language. It
has features to process text files and to perform system management tasks.

Security Fix(es):

  * rubygems: Installing a malicious gem may lead to arbitrary code execution
(CVE-2019-8324)

  * rubygems: Escape sequence injection vulnerability in gem owner
(CVE-2019-8322)

  * rubygems: Escape sequence injection vulnerability in API response
handling (CVE-2019-8323)

  * rubygems: Escape sequence injection vulnerability in errors
(CVE-2019-8325)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'ruby' package(s) on CentOS 7." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~2.0.0.648~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-devel", rpm: "ruby-devel~2.0.0.648~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-doc", rpm: "ruby-doc~2.0.0.648~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-bigdecimal", rpm: "rubygem-bigdecimal~1.2.0~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-io-console", rpm: "rubygem-io-console~0.4.2~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-json", rpm: "rubygem-json~1.7.7~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-minitest", rpm: "rubygem-minitest~4.3.2~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-psych", rpm: "rubygem-psych~2.0.0~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rake", rpm: "rubygem-rake~0.9.6~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rdoc", rpm: "rubygem-rdoc~4.0.0~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygems", rpm: "rubygems~2.0.14.1~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygems-devel", rpm: "rubygems-devel~2.0.14.1~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-irb", rpm: "ruby-irb~2.0.0.648~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-libs", rpm: "ruby-libs~2.0.0.648~35.el7_6", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-tcltk", rpm: "ruby-tcltk~2.0.0.648~35.el7_6", rls: "CentOS7" ) )){
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
