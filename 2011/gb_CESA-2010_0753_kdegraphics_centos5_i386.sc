if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2010-October/017061.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880578" );
	script_version( "2020-12-29T11:25:32+0000" );
	script_tag( name: "last_modification", value: "2020-12-29 11:25:32 +0000 (Tue, 29 Dec 2020)" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2010:0753" );
	script_cve_id( "CVE-2010-3702", "CVE-2010-3704" );
	script_name( "CentOS Update for kdegraphics CESA-2010:0753 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kdegraphics'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "kdegraphics on CentOS 5" );
	script_tag( name: "insight", value: "The kdegraphics packages contain applications for the K Desktop
  Environment, including KPDF, a viewer for Portable Document Format (PDF)
  files.

  An uninitialized pointer use flaw was discovered in KPDF. An attacker could
  create a malicious PDF file that, when opened, would cause KPDF to crash
  or, potentially, execute arbitrary code. (CVE-2010-3702)

  An array index error was found in the way KPDF parsed PostScript Type 1
  fonts embedded in PDF documents. An attacker could create a malicious PDF
  file that, when opened, would cause KPDF to crash or, potentially, execute
  arbitrary code. (CVE-2010-3704)

  Users are advised to upgrade to these updated packages, which contain
  backported patches to correct these issues." );
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
	if(( res = isrpmvuln( pkg: "kdegraphics", rpm: "kdegraphics~3.5.4~17.el5_5.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdegraphics-devel", rpm: "kdegraphics-devel~3.5.4~17.el5_5.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

