if(description){
	script_tag( name: "affected", value: "thunderbird on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2013-0775,
  CVE-2013-0780, CVE-2013-0782, CVE-2013-0783)

  It was found that, after canceling a proxy server's authentication
  prompt, the address bar continued to show the requested site's address. An
  attacker could use this flaw to conduct phishing attacks by tricking a
  user into believing they are viewing trusted content. (CVE-2013-0776)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Nils, Abhishek Arya, Olli Pettay, Christoph Diehl,
  Gary Kwong, Jesse Ruderman, Andrew McCreight, Joe Drew, Wayne Mery, and
  Michal Zalewski as the original reporters of these issues.

  Note: All issues cannot be exploited by a specially-crafted HTML mail
  message as JavaScript is disabled by default for mail messages. They could
  be exploited another way in Thunderbird, for example, when viewing the full
  remote content of an RSS feed.

  Important: This erratum upgrades Thunderbird to version 17.0.3 ESR.
  Thunderbird 17 is not completely backwards-compatible with all Mozilla
  add-ons and Thunderbird plug-ins that worked with Thunderbird 10.0.
  Thunderbird 17 checks compatibility on first-launch, and, depending on the
  individual configuration and the installed add-ons and plug-ins, may
  disable said Add-ons and plug-ins, or attempt to check for updates and
  upgrade them. Add-ons and plug-ins may have to be manually updated.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 17.0.3 ESR, which corrects these issues. After
  installing the update, Thunderbird must be restarted for the changes to
  take effect." );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-February/019246.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881605" );
	script_version( "2020-08-11T09:13:39+0000" );
	script_tag( name: "last_modification", value: "2020-08-11 09:13:39 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-22 10:04:54 +0530 (Fri, 22 Feb 2013)" );
	script_cve_id( "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:0272" );
	script_name( "CentOS Update for thunderbird CESA-2013:0272 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~17.0.3~1.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

