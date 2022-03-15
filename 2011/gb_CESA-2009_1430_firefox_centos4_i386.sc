if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-September/016133.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880901" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:1430" );
	script_cve_id( "CVE-2009-2654", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079" );
	script_name( "CentOS Update for firefox CESA-2009:1430 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "firefox on CentOS 4" );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox. nspr provides the Netscape
  Portable Runtime (NSPR).

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2009-3070, CVE-2009-3071, CVE-2009-3072, CVE-2009-3074,
  CVE-2009-3075)

  A use-after-free flaw was found in Firefox. An attacker could use this flaw
  to crash Firefox or, potentially, execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2009-3077)

  A flaw was found in the way Firefox handles malformed JavaScript. A website
  with an object containing malicious JavaScript could execute that
  JavaScript with the privileges of the user running Firefox. (CVE-2009-3079)

  Descriptions in the dialogs when adding and removing PKCS #11 modules were
  not informative. An attacker able to trick a user into installing a
  malicious PKCS #11 module could use this flaw to install their own
  Certificate Authority certificates on a user's machine, making it possible
  to trick the user into believing they are viewing a trusted site or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2009-3076)

  A flaw was found in the way Firefox displays the address bar when
  window.open() is called in a certain way. An attacker could use this flaw
  to conceal a malicious URL, possibly tricking a user into believing they
  are viewing a trusted site. (CVE-2009-2654)

  A flaw was found in the way Firefox displays certain Unicode characters. An
  attacker could use this flaw to conceal a malicious URL, possibly tricking
  a user into believing they are viewing a trusted site. (CVE-2009-3078)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.14. You can find a link to the Mozilla
  advisories in the References section of this errata.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.14, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect." );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~3.0.14~1.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nspr", rpm: "nspr~4.7.5~1.el4_8", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nspr-devel", rpm: "nspr-devel~4.7.5~1.el4_8", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

