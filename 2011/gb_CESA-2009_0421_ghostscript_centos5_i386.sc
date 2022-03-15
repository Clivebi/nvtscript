if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-April/015790.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880717" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:0421" );
	script_cve_id( "CVE-2007-6725", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0792", "CVE-2009-0583" );
	script_name( "CentOS Update for ghostscript CESA-2009:0421 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "ghostscript on CentOS 5" );
	script_tag( name: "insight", value: "Ghostscript is a set of software that provides a PostScript interpreter, a
  set of C procedures (the Ghostscript library, which implements the graphics
  capabilities in the PostScript language) and an interpreter for Portable
  Document Format (PDF) files.

  It was discovered that the Red Hat Security Advisory RHSA-2009:0345 did not
  address all possible integer overflow flaws in Ghostscript's International
  Color Consortium Format library (icclib). Using specially-crafted ICC
  profiles, an attacker could create a malicious PostScript or PDF file with
  embedded images that could cause Ghostscript to crash or, potentially,
  execute arbitrary code when opened. (CVE-2009-0792)

  A buffer overflow flaw and multiple missing boundary checks were found in
  Ghostscript. An attacker could create a specially-crafted PostScript or PDF
  file that could cause Ghostscript to crash or, potentially, execute
  arbitrary code when opened. (CVE-2008-6679, CVE-2007-6725, CVE-2009-0196)

  Red Hat would like to thank Alin Rad Pop of Secunia Research for
  responsibly reporting the CVE-2009-0196 flaw.

  Users of ghostscript are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues." );
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
	if(( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~8.15.2~9.4.el5_3.7", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ghostscript-devel", rpm: "ghostscript-devel~8.15.2~9.4.el5_3.7", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ghostscript-gtk", rpm: "ghostscript-gtk~8.15.2~9.4.el5_3.7", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
