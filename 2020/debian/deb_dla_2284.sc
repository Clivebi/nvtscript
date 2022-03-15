if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892284" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2019-14868" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-09 13:46:00 +0000 (Fri, 09 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-07-21 03:01:34 +0000 (Tue, 21 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for ksh (DLA-2284-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2284-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ksh'
  package(s) announced via the DLA-2284-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in the way it evaluates certain
environment variables. An attacker could use this
flaw to override or bypass environment restrictions
to execute shell commands. Services and
applications that allow remote unauthenticated
attackers to provide one of those environment
variables could allow them to exploit this issue
remotely." );
	script_tag( name: "affected", value: "'ksh' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
93u+20120801-3.1+deb9u1.

We recommend that you upgrade your ksh packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ksh", ver: "93u+20120801-3.1+deb9u1", rls: "DEB9" ) )){
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

