if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704601" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-20373" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-24 15:11:00 +0000 (Fri, 24 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-10 14:23:39 +0000 (Fri, 10 Jan 2020)" );
	script_name( "Debian Security Advisory DSA 4601-1 (ldm - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4601.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4601-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ldm'
  package(s) announced via the DSA-4601-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that a hook script of ldm, the display manager for the
Linux Terminal Server Project, incorrectly parsed responses from an SSH
server, which could result in local root privilege escalation." );
	script_tag( name: "affected", value: "'ldm' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 2:2.2.18-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 2:2.18.06-1+deb10u1.

We recommend that you upgrade your ldm packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ldm", ver: "2:2.18.06-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ldm-server", ver: "2:2.18.06-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ldm", ver: "2:2.2.18-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ldm-server", ver: "2:2.2.18-2+deb9u1", rls: "DEB9" ) )){
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

