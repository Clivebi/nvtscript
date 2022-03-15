if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892299" );
	script_version( "2021-09-14T05:54:32+0000" );
	script_cve_id( "CVE-2020-15862" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 05:54:32 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-04 14:58:00 +0000 (Fri, 04 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-07-31 03:00:10 +0000 (Fri, 31 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for net-snmp (DLA-2299-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2299-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/965166" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'net-snmp'
  package(s) announced via the DLA-2299-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A privilege escalation vulnerability was discovered in
Net-SNMP, a set of tools for collecting and organising information
about devices on computer networks.

Upstream notes that:

  * It is still possible to enable this MIB via the --with-mib-modules configure option.

  * Another MIB that provides similar functionality, namely
ucd-snmp/extensible, is disabled by default.

  * The security risk of ucd-snmp/pass and ucd-snmp/pass_persist is
lower since these modules only introduce a security risk if the
invoked scripts are exploitable." );
	script_tag( name: "affected", value: "'net-snmp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this issue has been fixed in net-snmp version
5.7.3+dfsg-1.7+deb9u2.

We recommend that you upgrade your net-snmp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-base", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-dev", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-perl", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp30", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp30-dbg", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-netsnmp", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmp", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmpd", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmptrapd", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tkmib", ver: "5.7.3+dfsg-1.7+deb9u2", rls: "DEB9" ) )){
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

