if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2010-July/016837.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880594" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2010:0565" );
	script_cve_id( "CVE-2010-2074" );
	script_name( "CentOS Update for w3m CESA-2010:0565 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'w3m'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "w3m on CentOS 5" );
	script_tag( name: "insight", value: "The w3m program is a pager (or text file viewer) that can also be used as a
  text mode web browser.

  It was discovered that w3m is affected by the previously published 'null
  prefix attack', caused by incorrect handling of NULL characters in X.509
  certificates. If an attacker is able to get a carefully-crafted certificate
  signed by a trusted Certificate Authority, the attacker could use the
  certificate during a man-in-the-middle attack and potentially confuse w3m
  into accepting it by mistake. (CVE-2010-2074)

  All w3m users should upgrade to these updated packages, which contain a
  backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please install the updated packages." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "w3m", rpm: "w3m~0.5.1~17.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "w3m-img", rpm: "w3m-img~0.5.1~17.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

