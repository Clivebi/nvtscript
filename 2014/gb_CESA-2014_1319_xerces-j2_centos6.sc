if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882045" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-01 16:59:53 +0530 (Wed, 01 Oct 2014)" );
	script_cve_id( "CVE-2013-4002" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_name( "CentOS Update for xerces-j2 CESA-2014:1319 centos6" );
	script_tag( name: "insight", value: "Apache Xerces for Java (Xerces-J) is a high performance, standards
compliant, validating XML parser written in Java. The xerces-j2 packages
provide Xerces-J version 2.

A resource consumption issue was found in the way Xerces-J handled XML
declarations. A remote attacker could use an XML document with a specially
crafted declaration using a long pseudo-attribute name that, when parsed by
an application using Xerces-J, would cause that application to use an
excessive amount of CPU. (CVE-2013-4002)

All xerces-j2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. Applications using the
Xerces-J must be restarted for this update to take effect." );
	script_tag( name: "affected", value: "xerces-j2 on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1319" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-September/020603.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xerces-j2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "xerces-j2", rpm: "xerces-j2~2.7.1~12.7.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-demo", rpm: "xerces-j2-demo~2.7.1~12.7.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-apis", rpm: "xerces-j2-javadoc-apis~2.7.1~12.7.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-impl", rpm: "xerces-j2-javadoc-impl~2.7.1~12.7.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-other", rpm: "xerces-j2-javadoc-other~2.7.1~12.7.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-xni", rpm: "xerces-j2-javadoc-xni~2.7.1~12.7.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-scripts", rpm: "xerces-j2-scripts~2.7.1~12.7.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

