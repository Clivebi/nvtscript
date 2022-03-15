if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882151" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-02 07:10:45 +0200 (Thu, 02 Apr 2015)" );
	script_cve_id( "CVE-2015-0801", "CVE-2015-0807", "CVE-2015-0813", "CVE-2015-0815", "CVE-2015-0816" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for firefox CESA-2015:0766 centos5" );
	script_tag( name: "summary", value: "Check the version of firefox" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2015-0813, CVE-2015-0815, CVE-2015-0801)

A flaw was found in the way documents were loaded via resource URLs in, for
example, Mozilla's PDF.js PDF file viewer. An attacker could use this flaw
to bypass certain restrictions and under certain conditions even execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2015-0816)

A flaw was found in the Beacon interface implementation in Firefox. A web
page containing malicious content could allow a remote attacker to conduct
a Cross-Site Request Forgery (CSRF) attack. (CVE-2015-0807)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, Byron Campen, Steve Fink, Mariusz
Mlynski, Christoph Kerschbaumer, Muneaki Nishimura, Olli Pettay, Boris
Zbarsky, and Aki Helin as the original reporters of these issues.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 31.6.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect." );
	script_tag( name: "affected", value: "firefox on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:0766" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-April/021011.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~31.6.0~2.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

