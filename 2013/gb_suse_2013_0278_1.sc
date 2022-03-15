if(description){
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2013-02/msg00003.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.850397" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-03-11 18:29:48 +0530 (Mon, 11 Mar 2013)" );
	script_cve_id( "CVE-2012-2695", "CVE-2012-5664", "CVE-2013-0155", "CVE-2013-0156", "CVE-2013-0333" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2013:0278-1" );
	script_name( "openSUSE: Security Advisory for ruby (openSUSE-SU-2013:0278-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.1" );
	script_tag( name: "affected", value: "ruby on openSUSE 12.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "This update updates the RubyOnRails 2.3 stack to 2.3.16,
  also this update updates the RubyOnRails 3.2 stack to
  3.2.11.

  Security and bugfixes were done, foremost: CVE-2013-0333: A
  JSON sql/code injection problem was fixed. CVE-2012-5664: A
  SQL Injection Vulnerability in Active Record was fixed.
  CVE-2012-2695: A SQL injection via nested hashes in
  conditions was fixed. CVE-2013-0155: Unsafe Query
  Generation Risk in Ruby on Rails was fixed. CVE-2013-0156:
  Multiple vulnerabilities in parameter parsing in Action
  Pack were fixed." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(release == "openSUSE12.1"){
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionmailer-2_3", rpm: "rubygem-actionmailer-2_3~2.3.16~3.9.3", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionmailer-2_3-doc", rpm: "rubygem-actionmailer-2_3-doc~2.3.16~3.9.3", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionmailer-2_3-testsuite", rpm: "rubygem-actionmailer-2_3-testsuite~2.3.16~3.9.3", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3", rpm: "rubygem-actionpack-2_3~2.3.16~3.16.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3-doc", rpm: "rubygem-actionpack-2_3-doc~2.3.16~3.16.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3-testsuite", rpm: "rubygem-actionpack-2_3-testsuite~2.3.16~3.16.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3", rpm: "rubygem-activerecord-2_3~2.3.16~3.12.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3-doc", rpm: "rubygem-activerecord-2_3-doc~2.3.16~3.12.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3-testsuite", rpm: "rubygem-activerecord-2_3-testsuite~2.3.16~3.12.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activeresource-2_3", rpm: "rubygem-activeresource-2_3~2.3.16~3.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activeresource-2_3-doc", rpm: "rubygem-activeresource-2_3-doc~2.3.16~3.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activeresource-2_3-testsuite", rpm: "rubygem-activeresource-2_3-testsuite~2.3.16~3.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activesupport-2_3", rpm: "rubygem-activesupport-2_3~2.3.16~3.13.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activesupport-2_3-doc", rpm: "rubygem-activesupport-2_3-doc~2.3.16~3.13.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rack-1_1", rpm: "rubygem-rack-1_1~1.1.5~3.5.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rack-1_1-doc", rpm: "rubygem-rack-1_1-doc~1.1.5~3.5.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rack-1_1-testsuite", rpm: "rubygem-rack-1_1-testsuite~1.1.5~3.5.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rails-2_3", rpm: "rubygem-rails-2_3~2.3.16~3.9.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rails-2_3-doc", rpm: "rubygem-rails-2_3-doc~2.3.16~3.9.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionmailer", rpm: "rubygem-actionmailer~2.3.16~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack", rpm: "rubygem-actionpack~2.3.16~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord", rpm: "rubygem-activerecord~2.3.16~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activeresource", rpm: "rubygem-activeresource~2.3.16~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activesupport", rpm: "rubygem-activesupport~2.3.16~2.7.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ubygem-rails", rpm: "ubygem-rails~2.3.16~2.7.1", rls: "openSUSE12.1" ) )){
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

