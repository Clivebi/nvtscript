if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-January/019217.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881584" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-04 09:54:44 +0530 (Mon, 04 Feb 2013)" );
	script_cve_id( "CVE-2012-5669" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2013:0216" );
	script_name( "CentOS Update for freetype CESA-2013:0216 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetype'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "freetype on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "FreeType is a free, high-quality, portable font engine that can open and
  manage font files. It also loads, hints, and renders individual glyphs
  efficiently.

  A flaw was found in the way the FreeType font rendering engine processed
  certain Glyph Bitmap Distribution Format (BDF) fonts. If a user loaded a
  specially-crafted font file with an application linked against FreeType, it
  could cause the application to crash or, possibly, execute arbitrary code
  with the privileges of the user running the application. (CVE-2012-5669)

  Users are advised to upgrade to these updated packages, which contain a
  backported patch to correct this issue. The X server must be restarted (log
  out, then log back in) for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "freetype", rpm: "freetype~2.2.1~32.el5_9.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-demos", rpm: "freetype-demos~2.2.1~32.el5_9.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-devel", rpm: "freetype-devel~2.2.1~32.el5_9.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

