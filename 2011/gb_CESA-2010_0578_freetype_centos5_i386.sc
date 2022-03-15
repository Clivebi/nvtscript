if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2010-August/016855.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880576" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2010:0578" );
	script_cve_id( "CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2527", "CVE-2010-2541" );
	script_name( "CentOS Update for freetype CESA-2010:0578 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetype'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "freetype on CentOS 5" );
	script_tag( name: "insight", value: "FreeType is a free, high-quality, portable font engine that can open and
  manage font files. It also loads, hints, and renders individual glyphs
  efficiently. The freetype packages for Red Hat Enterprise Linux 4 provide
  both the FreeType 1 and FreeType 2 font engines. The freetype packages for
  Red Hat Enterprise Linux 5 provide only the FreeType 2 font engine.

  An invalid memory management flaw was found in the way the FreeType font
  engine processed font files. If a user loaded a carefully-crafted font file
  with an application linked against FreeType, it could cause the application
  to crash or, possibly, execute arbitrary code with the privileges of the
  user running the application. (CVE-2010-2498)

  An integer overflow flaw was found in the way the FreeType font engine
  processed font files. If a user loaded a carefully-crafted font file with
  an application linked against FreeType, it could cause the application to
  crash or, possibly, execute arbitrary code with the privileges of the user
  running the application. (CVE-2010-2500)

  Several buffer overflow flaws were found in the way the FreeType font
  engine processed font files. If a user loaded a carefully-crafted font file
  with an application linked against FreeType, it could cause the application
  to crash or, possibly, execute arbitrary code with the privileges of the
  user running the application. (CVE-2010-2499, CVE-2010-2519)

  Several buffer overflow flaws were found in the FreeType demo applications.
  If a user loaded a carefully-crafted font file with a demo application, it
  could cause the application to crash or, possibly, execute arbitrary code
  with the privileges of the user running the application. (CVE-2010-2527,
  CVE-2010-2541)

  Red Hat would like to thank Robert Swiecki of the Google Security Team for
  the discovery of the CVE-2010-2498, CVE-2010-2500, CVE-2010-2499,
  CVE-2010-2519, and CVE-2010-2527 issues.

  Note: All of the issues in this erratum only affect the FreeType 2 font
  engine.

  Users are advised to upgrade to these updated packages, which contain
  backported patches to correct these issues. The X server must be restarted
  (log out, then log back in) for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "freetype", rpm: "freetype~2.2.1~25.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-demos", rpm: "freetype-demos~2.2.1~25.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-devel", rpm: "freetype-devel~2.2.1~25.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

