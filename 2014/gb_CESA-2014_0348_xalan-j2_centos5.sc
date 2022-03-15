if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881914" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-03 12:06:25 +0530 (Thu, 03 Apr 2014)" );
	script_cve_id( "CVE-2014-0107" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for xalan-j2 CESA-2014:0348 centos5" );
	script_tag( name: "affected", value: "xalan-j2 on CentOS 5" );
	script_tag( name: "insight", value: "Xalan-Java is an XSLT processor for transforming XML documents
into HTML, text, or other XML document types.

It was found that the secure processing feature of Xalan-Java had
insufficient restrictions defined for certain properties and features.
A remote attacker able to provide Extensible Stylesheet Language
Transformations (XSLT) content to be processed by an application using
Xalan-Java could use this flaw to bypass the intended constraints of the
secure processing feature. Depending on the components available in the
classpath, this could lead to arbitrary remote code execution in the
context of the application server running the application that uses
Xalan-Java. (CVE-2014-0107)

All xalan-j2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0348" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-April/020239.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xalan-j2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "xalan-j2", rpm: "xalan-j2~2.7.0~6jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xalan-j2-demo", rpm: "xalan-j2-demo~2.7.0~6jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xalan-j2-javadoc", rpm: "xalan-j2-javadoc~2.7.0~6jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xalan-j2-manual", rpm: "xalan-j2-manual~2.7.0~6jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xalan-j2-xsltc", rpm: "xalan-j2-xsltc~2.7.0~6jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

