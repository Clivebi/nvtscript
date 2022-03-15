if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-November/018977.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881534" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-09 09:33:53 +0530 (Fri, 09 Nov 2012)" );
	script_cve_id( "CVE-2012-4540" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:1434" );
	script_name( "CentOS Update for icedtea-web CESA-2012:1434 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "icedtea-web on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The IcedTea-Web project provides a Java web browser plug-in and an
  implementation of Java Web Start, which is based on the Netx project. It
  also contains a configuration tool for managing deployment settings for the
  plug-in and Web Start implementations.

  A buffer overflow flaw was found in the IcedTea-Web plug-in. Visiting a
  malicious web page could cause a web browser using the IcedTea-Web plug-in
  to crash or, possibly, execute arbitrary code. (CVE-2012-4540)

  Red Hat would like to thank Arthur Gerkis for reporting this issue.

  This erratum also upgrades IcedTea-Web to version 1.2.2. Refer to the NEWS
  file, linked to in the References, for further information.

  All IcedTea-Web users should upgrade to these updated packages, which
  resolve this issue. Web browsers using the IcedTea-Web browser plug-in must
  be restarted for this update to take effect." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "icedtea-web", rpm: "icedtea-web~1.2.2~1.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "icedtea-web-javadoc", rpm: "icedtea-web-javadoc~1.2.2~1.el6_3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

