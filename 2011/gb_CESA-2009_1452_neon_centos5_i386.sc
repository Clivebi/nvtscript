if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-October/016252.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880713" );
	script_version( "2020-05-26T08:07:04+0000" );
	script_tag( name: "last_modification", value: "2020-05-26 08:07:04 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_xref( name: "CESA", value: "2009:1452" );
	script_cve_id( "CVE-2009-2473", "CVE-2009-2474" );
	script_name( "CentOS Update for neon CESA-2009:1452 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'neon'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "neon on CentOS 5" );
	script_tag( name: "insight", value: "neon is an HTTP and WebDAV client library, with a C interface. It provides
  a high-level interface to HTTP and WebDAV methods along with a low-level
  interface for HTTP request handling. neon supports persistent connections,
  proxy servers, basic, digest and Kerberos authentication, and has complete
  SSL support.

  It was discovered that neon is affected by the previously published 'null
  prefix attack', caused by incorrect handling of NULL characters in X.509
  certificates. If an attacker is able to get a carefully-crafted certificate
  signed by a trusted Certificate Authority, the attacker could use the
  certificate during a man-in-the-middle attack and potentially confuse an
  application using the neon library into accepting it by mistake.
  (CVE-2009-2474)

  A denial of service flaw was found in the neon Extensible Markup Language
  (XML) parser. A remote attacker (malicious DAV server) could provide a
  specially-crafted XML document that would cause excessive memory and CPU
  consumption if an application using the neon XML parser was tricked into
  processing it. (CVE-2009-2473)

  All neon users should upgrade to these updated packages, which contain
  backported patches to correct these issues. Applications using the neon
  HTTP and WebDAV client library, such as cadaver, must be restarted for this
  update to take effect." );
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
	if(( res = isrpmvuln( pkg: "neon", rpm: "neon~0.25.5~10.el5_4.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "neon-devel", rpm: "neon-devel~0.25.5~10.el5_4.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

