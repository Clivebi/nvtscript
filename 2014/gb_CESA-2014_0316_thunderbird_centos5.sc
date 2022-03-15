if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881905" );
	script_version( "2020-08-13T08:33:13+0000" );
	script_tag( name: "last_modification", value: "2020-08-13 08:33:13 +0000 (Thu, 13 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-03-20 09:46:31 +0530 (Thu, 20 Mar 2014)" );
	script_cve_id( "CVE-2014-1493", "CVE-2014-1497", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for thunderbird CESA-2014:0316 centos5" );
	script_tag( name: "affected", value: "thunderbird on CentOS 5" );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2014-1493, CVE-2014-1510, CVE-2014-1511, CVE-2014-1512,
CVE-2014-1513, CVE-2014-1514)

Several information disclosure flaws were found in the way Thunderbird
processed malformed web content. An attacker could use these flaws to gain
access to sensitive information such as cross-domain content or protected
memory addresses or, potentially, cause Thunderbird to crash.
(CVE-2014-1497, CVE-2014-1508, CVE-2014-1505)

A memory corruption flaw was found in the way Thunderbird rendered certain
PDF files. An attacker able to trick a user into installing a malicious
extension could use this flaw to crash Thunderbird or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2014-1509)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij,
Jesse Ruderman, Dan Gohman, Christoph Diehl, Atte Kettunen, Tyson Smith,
Jesse Schwartzentruber, John Thomson, Robert O'Callahan, Mariusz Mlynski,
Juri Aedla, George Hotz, and the security research firm VUPEN as the
original reporters of these issues.

Note: All of the above issues cannot be exploited by a specially-crafted
HTML mail message as JavaScript is disabled by default for mail messages.
They could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 24.4.0. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 24.4.0, which corrects these issues.
After installing the update, Thunderbird must be restarted for the changes
to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0316" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-March/020219.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~24.4.0~1.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

