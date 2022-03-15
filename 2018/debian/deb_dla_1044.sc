if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891044" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2016-10396" );
	script_name( "Debian LTS: Security Advisory for ipsec-tools (DLA-1044-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-27 17:52:00 +0000 (Thu, 27 Jul 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00039.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ipsec-tools on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1:0.8.0-14+deb7u2.

We recommend that you upgrade your ipsec-tools packages." );
	script_tag( name: "summary", value: "The racoon daemon in IPsec-Tools 0.8.2 and earlier contains a remotely
exploitable computational-complexity attack when parsing and storing
ISAKMP fragments. The implementation permits a remote attacker to
exhaust computational resources on the remote endpoint by repeatedly
sending ISAKMP fragment packets in a particular order such that the
worst-case computational complexity is realized in the algorithm
utilized to determine if reassembly of the fragments can take place." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ipsec-tools", ver: "1:0.8.0-14+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "racoon", ver: "1:0.8.0-14+deb7u2", rls: "DEB7" ) )){
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

