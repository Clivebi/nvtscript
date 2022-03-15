if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703780" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-0358" );
	script_name( "Debian Security Advisory DSA 3780-1 (ntfs-3g - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-03 12:11:13 +0530 (Fri, 03 Feb 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3780.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ntfs-3g on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1:2014.2.15AR.2-1+deb8u3.

For the unstable distribution (sid), this problem has been fixed in
version 1:2016.2.22AR.1-4.

We recommend that you upgrade your ntfs-3g packages." );
	script_tag( name: "summary", value: "Jann Horn of Google Project Zero
discovered that NTFS-3G, a read-write NTFS driver for FUSE, does not scrub the
environment before executing modprobe with elevated privileges. A local user can
take advantage of this flaw for local root privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2014.2.15AR.2-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-dbg", ver: "1:2014.2.15AR.2-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntfs-3g-dev", ver: "1:2014.2.15AR.2-1+deb8u3", rls: "DEB8" ) ) != NULL){
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

