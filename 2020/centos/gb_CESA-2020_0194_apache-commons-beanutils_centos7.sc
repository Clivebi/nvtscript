if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883171" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2019-10086" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-01-29 04:01:10 +0000 (Wed, 29 Jan 2020)" );
	script_name( "CentOS: Security Advisory for apache-commons-beanutils (CESA-2020:0194)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:0194" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-January/035618.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache-commons-beanutils'
  package(s) announced via the CESA-2020:0194 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Apache Commons BeanUtils library provides utility methods for accessing
and modifying properties of arbitrary JavaBeans.

Security Fix(es):

  * apache-commons-beanutils: does not suppresses the class property in
PropertyUtilsBean by default (CVE-2019-10086)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'apache-commons-beanutils' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "apache-commons-beanutils", rpm: "apache-commons-beanutils~1.8.3~15.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache-commons-beanutils-javadoc", rpm: "apache-commons-beanutils-javadoc~1.8.3~15.el7_7", rls: "CentOS7" ) )){
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
