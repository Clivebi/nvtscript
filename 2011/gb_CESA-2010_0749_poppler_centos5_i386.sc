if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2010-October/017056.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880575" );
	script_version( "2020-12-29T11:25:32+0000" );
	script_tag( name: "last_modification", value: "2020-12-29 11:25:32 +0000 (Tue, 29 Dec 2020)" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2010:0749" );
	script_cve_id( "CVE-2010-3702", "CVE-2010-3704" );
	script_name( "CentOS Update for poppler CESA-2010:0749 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "poppler on CentOS 5" );
	script_tag( name: "insight", value: "Poppler is a Portable Document Format (PDF) rendering library, used by
  applications such as Evince.

  An uninitialized pointer use flaw was discovered in poppler. An attacker
  could create a malicious PDF file that, when opened, would cause
  applications that use poppler (such as Evince) to crash or, potentially,
  execute arbitrary code. (CVE-2010-3702)

  An array index error was found in the way poppler parsed PostScript Type 1
  fonts embedded in PDF documents. An attacker could create a malicious PDF
  file that, when opened, would cause applications that use poppler (such as
  Evince) to crash or, potentially, execute arbitrary code. (CVE-2010-3704)

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
	if(( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.5.4~4.4.el5_5.14", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "poppler-devel", rpm: "poppler-devel~0.5.4~4.4.el5_5.14", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "poppler-utils", rpm: "poppler-utils~0.5.4~4.4.el5_5.14", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

