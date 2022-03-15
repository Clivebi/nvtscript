if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891816" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-12248", "CVE-2019-12497" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-23 15:15:00 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-06-12 02:00:10 +0000 (Wed, 12 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for otrs2 (DLA-1816-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1816-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'otrs2'
  package(s) announced via the DLA-1816-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two security vulnerabilities were discovered in the Open Ticket
Request System that could lead to information disclosure or privilege
escalation. New configuration options were added to resolve those
problems.

CVE-2019-12248

An attacker could send a malicious email to an OTRS system. If a
logged in agent user quotes it, the email could cause the browser to
load external image resources.

CVE-2019-12497

In the customer or external frontend, personal information of agents
can be disclosed like Name and mail address in external notes." );
	script_tag( name: "affected", value: "'otrs2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u10.

We recommend that you upgrade your otrs2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "otrs", ver: "3.3.18-1+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "otrs2", ver: "3.3.18-1+deb8u10", rls: "DEB8" ) )){
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

