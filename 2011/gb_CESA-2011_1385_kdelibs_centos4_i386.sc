if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-November/018167.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881040" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-11 09:54:47 +0530 (Fri, 11 Nov 2011)" );
	script_xref( name: "CESA", value: "2011:1385" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-3365" );
	script_name( "CentOS Update for kdelibs CESA-2011:1385 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kdelibs'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "kdelibs on CentOS 4" );
	script_tag( name: "insight", value: "The kdelibs and kdelibs3 packages provide libraries for the K Desktop
  Environment (KDE).

  An input sanitization flaw was found in the KSSL (KDE SSL Wrapper) API. An
  attacker could supply a specially-crafted SSL certificate (for example, via
  a web page) to an application using KSSL, such as the Konqueror web
  browser, causing misleading information to be presented to the user,
  possibly tricking them into accepting the certificate as valid.
  (CVE-2011-3365)

  Users should upgrade to these updated packages, which contain a backported
  patch to correct this issue. The desktop must be restarted (log out, then
  log back in) for this update to take effect." );
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
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "kdelibs", rpm: "kdelibs~3.3.1~18.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kdelibs-devel", rpm: "kdelibs-devel~3.3.1~18.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

