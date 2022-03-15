if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-September/018071.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881308" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:20:19 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-3193" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2011:1325" );
	script_name( "CentOS Update for evolution28-pango CESA-2011:1325 centos4 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evolution28-pango'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "evolution28-pango on CentOS 4" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Pango is a library used for the layout and rendering of internationalized
  text.

  A buffer overflow flaw was found in HarfBuzz, an OpenType text shaping
  engine used in Pango. If a user loaded a specially-crafted font file with
  an application that uses Pango, it could cause the application to crash or,
  possibly, execute arbitrary code with the privileges of the user running
  the application. (CVE-2011-3193)

  Users of evolution28-pango are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. After
  installing this update, you must restart your system or restart the X
  server for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "evolution28-pango", rpm: "evolution28-pango~1.14.9~13.el4_11", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "evolution28-pango-devel", rpm: "evolution28-pango-devel~1.14.9~13.el4_11", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

