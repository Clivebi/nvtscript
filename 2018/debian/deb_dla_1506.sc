if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891506" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2017-5715", "CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3639", "CVE-2018-3640", "CVE-2018-3646" );
	script_name( "Debian LTS: Security Advisory for intel-microcode (DLA-1506-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-17 00:00:00 +0200 (Mon, 17 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "intel-microcode on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.20180807a.1~deb8u1.

We recommend that you upgrade your intel-microcode packages." );
	script_tag( name: "summary", value: "Security researchers identified speculative execution side-channel
methods which have the potential to improperly gather sensitive data
from multiple types of computing devices with different vendors
processors and operating systems.

This update requires an update to the intel-microcode package, which is
non-free. It is related to DLA-1446-1 and adds more mitigations for
additional types of Intel processors." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20180807a.1~deb8u1", rls: "DEB8" ) )){
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

