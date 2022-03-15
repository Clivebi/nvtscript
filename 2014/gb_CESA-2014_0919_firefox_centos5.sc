if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881978" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-28 16:37:17 +0530 (Mon, 28 Jul 2014)" );
	script_cve_id( "CVE-2014-1547", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for firefox CESA-2014:0919 centos5" );
	script_tag( name: "affected", value: "firefox on CentOS 5" );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner
provides the XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2014-1547, CVE-2014-1555, CVE-2014-1556, CVE-2014-1557)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, David Keeler, Byron Campen, Jethro
Beekman, Patrick Cozzi, and Mozilla community member John as the original
reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 24.7.0 ESR. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 24.7.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0919" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-July/020429.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~24.7.0~1.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

