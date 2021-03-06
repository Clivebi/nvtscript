if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-September/msg00038.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870492" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)" );
	script_xref( name: "RHSA", value: "2011:1326-01" );
	script_cve_id( "CVE-2011-3193" );
	script_name( "RedHat Update for pango RHSA-2011:1326-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pango'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_tag( name: "affected", value: "pango on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Pango is a library used for the layout and rendering of internationalized
  text.

  A buffer overflow flaw was found in HarfBuzz, an OpenType text shaping
  engine used in Pango. If a user loaded a specially-crafted font file with
  an application that uses Pango, it could cause the application to crash or,
  possibly, execute arbitrary code with the privileges of the user running
  the application. (CVE-2011-3193)

  Users of pango are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, you must restart your system or restart the X server for the update
  to take effect." );
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
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "pango", rpm: "pango~1.14.9~8.el5_7.3", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango-debuginfo", rpm: "pango-debuginfo~1.14.9~8.el5_7.3", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango-devel", rpm: "pango-devel~1.14.9~8.el5_7.3", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

