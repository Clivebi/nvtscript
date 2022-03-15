if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-December/018324.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881058" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-12-16 11:10:58 +0530 (Fri, 16 Dec 2011)" );
	script_xref( name: "CESA", value: "2011:1815" );
	script_cve_id( "CVE-2011-4599" );
	script_name( "CentOS Update for icu CESA-2011:1815 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icu'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "icu on CentOS 5" );
	script_tag( name: "insight", value: "The International Components for Unicode (ICU) library provides robust and
  full-featured Unicode services.

  A stack-based buffer overflow flaw was found in the way ICU performed
  variant canonicalization for some locale identifiers. If a
  specially-crafted locale representation was opened in an application
  linked against ICU, it could cause the application to crash or, possibly,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-4599)

  All users of ICU should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. All applications linked against
  ICU must be restarted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "icu", rpm: "icu~3.6~5.16.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libicu", rpm: "libicu~3.6~5.16.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libicu-devel", rpm: "libicu-devel~3.6~5.16.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libicu-doc", rpm: "libicu-doc~3.6~5.16.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

