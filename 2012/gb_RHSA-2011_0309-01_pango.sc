if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-March/msg00005.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870614" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-09 10:34:14 +0530 (Mon, 09 Jul 2012)" );
	script_cve_id( "CVE-2011-0064" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "RHSA", value: "2011:0309-01" );
	script_name( "RedHat Update for pango RHSA-2011:0309-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pango'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "pango on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Pango is a library used for the layout and rendering of internationalized
  text.

  It was discovered that Pango did not check for memory reallocation failures
  in the hb_buffer_ensure() function. An attacker able to trigger a
  reallocation failure by passing sufficiently large input to an application
  using Pango could use this flaw to crash the application or, possibly,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-0064)

  Red Hat would like to thank the Mozilla Security Team for reporting this
  issue.

  All pango users should upgrade to these updated packages, which contain a
  backported patch to correct this issue. After installing this update, you
  must restart your system or restart the X server for the update to take
  effect." );
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
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "pango", rpm: "pango~1.28.1~3.el6_0.5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango-debuginfo", rpm: "pango-debuginfo~1.28.1~3.el6_0.5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango-devel", rpm: "pango-devel~1.28.1~3.el6_0.5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

