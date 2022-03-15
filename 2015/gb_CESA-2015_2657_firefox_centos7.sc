if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882349" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-17 05:08:47 +0100 (Thu, 17 Dec 2015)" );
	script_cve_id( "CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7210", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7222" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for firefox CESA-2015:2657 centos7" );
	script_tag( name: "summary", value: "Check the version of firefox" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web
browser. XULRunner provides the XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2015-7201, CVE-2015-7205, CVE-2015-7210, CVE-2015-7212,
CVE-2015-7213, CVE-2015-7222)

A flaw was found in the way Firefox handled content using the 'data:' and
'view-source:' URIs. An attacker could use this flaw to bypass the
same-origin policy and read data from cross-site URLs and local files.
(CVE-2015-7214)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Andrei Vaida, Jesse Ruderman, Bob Clary, Looben Yang,
Abhishek Arya, Ronald Crane, Gerald Squelart, and Tsubasa Iinuma as the
original reporters of these issues.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 38.5.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect." );
	script_tag( name: "affected", value: "firefox on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:2657" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-December/021547.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~38.5.0~3.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

