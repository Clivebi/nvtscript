if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881612" );
	script_version( "2020-08-11T09:13:39+0000" );
	script_tag( name: "last_modification", value: "2020-08-11 09:13:39 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-22 10:07:19 +0530 (Fri, 22 Feb 2013)" );
	script_cve_id( "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2013:0271" );
	script_name( "CentOS Update for firefox CESA-2013:0271 centos6" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-February/019250.html" );
	script_xref( name: "URL", value: "https://access.redhat.com/knowledge/solutions/294303" );
	script_xref( name: "URL", value: "https://access.redhat.com/knowledge/articles/11258" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "firefox on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A
  web page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2013-0775, CVE-2013-0780, CVE-2013-0782,
  CVE-2013-0783)

  It was found that, after canceling a proxy server's authentication
  prompt, the address bar continued to show the requested site's address. An
  attacker could use this flaw to conduct phishing attacks by tricking a
  user into believing they are viewing a trusted site. (CVE-2013-0776)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Nils, Abhishek Arya, Olli Pettay, Christoph Diehl,
  Gary Kwong, Jesse Ruderman, Andrew McCreight, Joe Drew, Wayne Mery, and
  Michal Zalewski as the original reporters of these issues.

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 17.0.3 ESR. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  Note that due to a Kerberos credentials change, the configuration steps
  described in the linked article may be required when using Firefox 17.0.3 ESR
  with the Enterprise Identity Management (IPA) web interface.

  Important: Firefox 17 is not completely backwards-compatible with all
  Mozilla add-ons and Firefox plug-ins that worked with Firefox 10.0.
  Firefox 17 checks compatibility on first-launch, and, depending on the
  individual configuration and the installed add-ons and plug-ins, may
  disable said Add-ons and plug-ins, or attempt to check for updates and
  upgrade them. Add-ons and plug-ins may have to be manually updated.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 17.0.3 ESR, which corrects these issues. After installing
  the update, Firefox must be restarted for the changes to take effect.

  4. Solution:

  Before applying this update, make sure all previously-released errata
  relevant to your system have been applied.

  This update is available via the Red Hat Network. Details on how to
  use the Red Hat Network to apply this update are available at
  the linked references.

  Description truncated, please see the referenced URL(s) for more information." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~17.0.3~1.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

