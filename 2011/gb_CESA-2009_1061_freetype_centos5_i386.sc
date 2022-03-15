if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-May/015894.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880811" );
	script_version( "2021-04-08T07:13:02+0000" );
	script_tag( name: "last_modification", value: "2021-04-08 07:13:02 +0000 (Thu, 08 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:1061" );
	script_cve_id( "CVE-2009-0946" );
	script_name( "CentOS Update for freetype CESA-2009:1061 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetype'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "freetype on CentOS 5" );
	script_tag( name: "insight", value: "FreeType is a free, high-quality, portable font engine that can open and
  manage font files. It also loads, hints, and renders individual glyphs
  efficiently. These packages provide the FreeType 2 font engine.

  Tavis Ormandy of the Google Security Team discovered several integer
  overflow flaws in the FreeType 2 font engine. If a user loaded a
  carefully-crafted font file with an application linked against FreeType 2,
  it could cause the application to crash or, possibly, execute arbitrary
  code with the privileges of the user running the application.
  (CVE-2009-0946)

  Users are advised to upgrade to these updated packages, which contain a
  backported patch to correct these issues. The X server must be restarted
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
	if(( res = isrpmvuln( pkg: "freetype", rpm: "freetype~2.2.1~21.el5_3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-demos", rpm: "freetype-demos~2.2.1~21.el5_3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-devel", rpm: "freetype-devel~2.2.1~21.el5_3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

