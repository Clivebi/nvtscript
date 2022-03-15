if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891877" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2018-11563", "CVE-2019-12248", "CVE-2019-12746", "CVE-2019-13458" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-15 02:00:15 +0000 (Thu, 15 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for otrs2 (DLA-1877-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1877-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'otrs2'
  package(s) announced via the DLA-1877-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security issues have been fixed in otrs2, a well known trouble
ticket system.

CVE-2018-11563

An attacker who is logged into OTRS as a customer can use the ticket
overview screen to disclose internal article information of their
customer tickets.

CVE-2019-12746

A user logged into OTRS as an agent might unknowingly disclose their
session ID by sharing the link of an embedded ticket article with
third parties. This identifier can be then potentially abused in
order to impersonate the agent user.

CVE-2019-13458

An attacker who is logged into OTRS as an agent user with
appropriate permissions can leverage OTRS tags in templates in order
to disclose hashed user passwords.

Due to an incomplete fix for CVE-2019-12248, viewing email attachments
was no longer possible. This update correctly implements the new
Ticket::Fronted::BlockLoadingRemoteContent option." );
	script_tag( name: "affected", value: "'otrs2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u11.

We recommend that you upgrade your otrs2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "otrs", ver: "3.3.18-1+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "otrs2", ver: "3.3.18-1+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}
exit( 0 );

