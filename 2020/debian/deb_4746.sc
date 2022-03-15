if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704746" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-15861", "CVE-2020-15862" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-04 11:15:00 +0000 (Fri, 04 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-08-17 03:00:06 +0000 (Mon, 17 Aug 2020)" );
	script_name( "Debian: Security Advisory for net-snmp (DSA-4746-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4746.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4746-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'net-snmp'
  package(s) announced via the DSA-4746-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in net-snmp, a suite of Simple
Network Management Protocol applications, which could lead to privilege
escalation." );
	script_tag( name: "affected", value: "'net-snmp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 5.7.3+dfsg-5+deb10u1.

We recommend that you upgrade your net-snmp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-base", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-dev", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-perl", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp30", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp30-dbg", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-netsnmp", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmp", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmpd", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmptrapd", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tkmib", ver: "5.7.3+dfsg-5+deb10u1", rls: "DEB10" ) )){
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

